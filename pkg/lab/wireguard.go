package lab

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

var (
	wgAgentBuildOnce sync.Once
	wgAgentBinPath   string
	wgAgentBuildErr  error
)

const containerWGAgentPath = "/tmp/netlab-wg-agent"

// buildWGAgent compiles the static pure-Go wireguard-go agent binary once per test process.
func buildWGAgent() (string, error) {
	wgAgentBuildOnce.Do(func() {
		_, thisFile, _, _ := runtime.Caller(0)
		repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
		agentSrc := filepath.Join(repoRoot, "internal", "wgagent")

		tmpFile, err := os.CreateTemp("", "netlab-wg-agent-*")
		if err != nil {
			wgAgentBuildErr = fmt.Errorf("create temp wg-agent binary: %w", err)
			return
		}
		_ = tmpFile.Close()
		wgAgentBinPath = tmpFile.Name()

		cmd := exec.Command("go", "build", "-o", wgAgentBinPath, agentSrc)
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
		if out, err := cmd.CombinedOutput(); err != nil {
			wgAgentBuildErr = fmt.Errorf("compile wgagent: %w (%s)", err, strings.TrimSpace(string(out)))
			return
		}
	})
	return wgAgentBinPath, wgAgentBuildErr
}

// WGKeyPair holds a WireGuard X25519 private and public key pair.
type WGKeyPair struct {
	PrivateKey string // Base64-encoded 32-byte key
	PublicKey  string // Base64-encoded 32-byte key
}

// GenerateWGKeyPair generates a Curve25519 key pair compatible with WireGuard.
func GenerateWGKeyPair() (WGKeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return WGKeyPair{}, fmt.Errorf("read random bytes: %w", err)
	}
	// Standard RFC 7748 clamping
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	key, err := ecdh.X25519().NewPrivateKey(priv[:])
	if err != nil {
		return WGKeyPair{}, fmt.Errorf("derive x25519 key: %w", err)
	}

	return WGKeyPair{
		PrivateKey: base64.StdEncoding.EncodeToString(priv[:]),
		PublicKey:  base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()),
	}, nil
}

// keyToHex converts a base64-encoded (or already hex-encoded) 32-byte WireGuard key to UAPI hex format.
func keyToHex(k string) (string, error) {
	k = strings.TrimSpace(k)
	if len(k) == 64 {
		if _, err := hex.DecodeString(k); err == nil {
			return strings.ToLower(k), nil
		}
	}
	raw, err := base64.StdEncoding.DecodeString(k)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("invalid 32-byte WireGuard key %q", k)
	}
	return hex.EncodeToString(raw), nil
}

// WGPeerConfig describes a remote WireGuard peer configuration.
type WGPeerConfig struct {
	PublicKey           string
	Endpoint            string   // e.g. "172.28.20.10:51820"
	AllowedIPs          []string // e.g. []string{"10.100.0.2/32"}
	PersistentKeepalive int      // optional seconds (0 to disable)
}

// WGInterfaceConfig describes a userspace wireguard-go interface to configure inside a Node.
type WGInterfaceConfig struct {
	Interface  string // defaults to "wg0" if empty
	Address    string // CIDR, e.g. "10.100.0.1/24"
	PrivateKey string
	ListenPort int // optional UDP port, e.g. 51820
	MTU        int // optional MTU (defaults to 1420)
	Peers      []WGPeerConfig
}

// SetupWireGuard starts a pure-Go userspace wireguard-go daemon inside the Node,
// configures it via the WireGuard UAPI protocol, assigns its overlay IP, and brings the TUN link up.
func (n *Node) SetupWireGuard(ctx context.Context, cfg WGInterfaceConfig) error {
	if n.t != nil {
		n.t.Helper()
	}

	iface := cfg.Interface
	if iface == "" {
		iface = "wg0"
	}

	hostBin, err := buildWGAgent()
	if err != nil {
		return err
	}

	if err := n.Container.CopyFileToContainer(ctx, hostBin, containerWGAgentPath, 0o755); err != nil {
		return fmt.Errorf("copy wg-agent to %s: %w", n.Name, err)
	}

	uapiConf, err := buildUAPIConfig(cfg)
	if err != nil {
		return fmt.Errorf("build uapi config for %s on %s: %w", iface, n.Name, err)
	}

	uapiPath := fmt.Sprintf("/tmp/%s.uapi", iface)
	readyPath := fmt.Sprintf("/tmp/%s.ready", iface)
	logPath := fmt.Sprintf("/tmp/%s.log", iface)
	pidPath := fmt.Sprintf("/tmp/%s.pid", iface)

	mtuFlag := ""
	if cfg.MTU > 0 {
		mtuFlag = fmt.Sprintf("-mtu %d", cfg.MTU)
	}

	startScript := fmt.Sprintf(
		"umask 077 && cat <<'EOF' > %s\n%sEOF\n"+
			"%s -iface %s %s -uapi %s -ready %s > %s 2>&1 & echo $! > %s; "+
			"for i in $(seq 1 50); do "+
			"  if [ -f %s ]; then rm -f %s; exit 0; fi; "+
			"  if ! kill -0 $(cat %s) 2>/dev/null; then cat %s >&2; exit 1; fi; "+
			"  sleep 0.02; "+
			"done; "+
			"cat %s >&2; exit 1",
		uapiPath, uapiConf,
		containerWGAgentPath, iface, mtuFlag, uapiPath, readyPath, logPath, pidPath,
		readyPath, uapiPath, pidPath, logPath, logPath,
	)

	if out, err := n.Exec(ctx, []string{"sh", "-c", startScript}); err != nil {
		return fmt.Errorf("start wireguard-go (%s) on %s: %w (output: %s)", iface, n.Name, err, out)
	}

	if _, err := n.Exec(ctx, []string{"ip", "addr", "add", cfg.Address, "dev", iface}); err != nil {
		return fmt.Errorf("assign address %s to %s on %s: %w", cfg.Address, iface, n.Name, err)
	}

	if _, err := n.Exec(ctx, []string{"ip", "link", "set", "up", "dev", iface}); err != nil {
		return fmt.Errorf("bring up %s on %s: %w", iface, n.Name, err)
	}

	return nil
}

// WireGuardStatus queries the UAPI socket of the running wireguard-go daemon inside the Node.
func (n *Node) WireGuardStatus(ctx context.Context, iface string) (string, error) {
	if iface == "" {
		iface = "wg0"
	}
	return n.Exec(ctx, []string{containerWGAgentPath, "-status", "-iface", iface})
}

func buildUAPIConfig(cfg WGInterfaceConfig) (string, error) {
	privHex, err := keyToHex(cfg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", privHex)
	if cfg.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", cfg.ListenPort)
	}
	fmt.Fprintf(&b, "replace_peers=true\n")

	for _, peer := range cfg.Peers {
		pubHex, err := keyToHex(peer.PublicKey)
		if err != nil {
			return "", fmt.Errorf("peer public key: %w", err)
		}
		fmt.Fprintf(&b, "public_key=%s\n", pubHex)
		if peer.Endpoint != "" {
			fmt.Fprintf(&b, "endpoint=%s\n", peer.Endpoint)
		}
		if len(peer.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "replace_allowed_ips=true\n")
			for _, cidr := range peer.AllowedIPs {
				fmt.Fprintf(&b, "allowed_ip=%s\n", cidr)
			}
		}
		if peer.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", peer.PersistentKeepalive)
		}
	}
	fmt.Fprintf(&b, "\n")
	return b.String(), nil
}
