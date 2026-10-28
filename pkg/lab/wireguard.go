package lab

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
)

// WGKeyPair holds a base64-encoded WireGuard X25519 private and public key pair.
type WGKeyPair struct {
	PrivateKey string
	PublicKey  string
}

// GenerateWGKeyPair generates a Curve25519 key pair compatible with WireGuard.
func GenerateWGKeyPair() (WGKeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return WGKeyPair{}, fmt.Errorf("read random bytes: %w", err)
	}
	// Standard RFC 7748 clamping used by `wg genkey`
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

// WGPeerConfig describes a remote WireGuard peer configuration.
type WGPeerConfig struct {
	PublicKey           string
	Endpoint            string   // e.g. "172.28.20.10:51820"
	AllowedIPs          []string // e.g. []string{"10.100.0.2/32"}
	PersistentKeepalive int      // optional seconds (0 to disable)
}

// WGInterfaceConfig describes a WireGuard interface to configure inside a Node.
type WGInterfaceConfig struct {
	Interface  string // defaults to "wg0" if empty
	Address    string // CIDR, e.g. "10.100.0.1/24"
	PrivateKey string
	ListenPort int // optional UDP port, e.g. 51820
	MTU        int // optional MTU
	Peers      []WGPeerConfig
}

// SetupWireGuard creates and configures a kernel WireGuard interface inside the node.
func (n *Node) SetupWireGuard(ctx context.Context, cfg WGInterfaceConfig) error {
	iface := cfg.Interface
	if iface == "" {
		iface = "wg0"
	}

	// Create interface and assign overlay IP
	if _, err := n.Exec(ctx, []string{"ip", "link", "add", "dev", iface, "type", "wireguard"}); err != nil {
		return fmt.Errorf("create wireguard interface %s on %s: %w", iface, n.Name, err)
	}
	if _, err := n.Exec(ctx, []string{"ip", "addr", "add", cfg.Address, "dev", iface}); err != nil {
		return fmt.Errorf("assign address %s to %s on %s: %w", cfg.Address, iface, n.Name, err)
	}
	if cfg.MTU > 0 {
		if _, err := n.Exec(ctx, []string{"ip", "link", "set", "dev", iface, "mtu", fmt.Sprintf("%d", cfg.MTU)}); err != nil {
			return fmt.Errorf("set mtu on %s (%s): %w", iface, n.Name, err)
		}
	}

	// Configure private key and listen port via `wg set`
	setCmd := fmt.Sprintf("umask 077 && printf '%%s' '%s' > /tmp/%s.key && wg set %s private-key /tmp/%s.key && rm -f /tmp/%s.key",
		cfg.PrivateKey, iface, iface, iface, iface)
	if cfg.ListenPort > 0 {
		setCmd += fmt.Sprintf(" && wg set %s listen-port %d", iface, cfg.ListenPort)
	}
	if _, err := n.Exec(ctx, []string{"sh", "-c", setCmd}); err != nil {
		return fmt.Errorf("configure wg private key on %s: %w", n.Name, err)
	}

	// Add peers
	for _, peer := range cfg.Peers {
		args := []string{"wg", "set", iface, "peer", peer.PublicKey}
		if peer.Endpoint != "" {
			args = append(args, "endpoint", peer.Endpoint)
		}
		if len(peer.AllowedIPs) > 0 {
			args = append(args, "allowed-ips", strings.Join(peer.AllowedIPs, ","))
		}
		if peer.PersistentKeepalive > 0 {
			args = append(args, "persistent-keepalive", fmt.Sprintf("%d", peer.PersistentKeepalive))
		}
		if _, err := n.Exec(ctx, args); err != nil {
			return fmt.Errorf("configure wg peer %s on %s: %w", peer.PublicKey, n.Name, err)
		}
	}

	// Bring interface up
	if _, err := n.Exec(ctx, []string{"ip", "link", "set", "up", "dev", iface}); err != nil {
		return fmt.Errorf("bring up %s on %s: %w", iface, n.Name, err)
	}

	return nil
}
