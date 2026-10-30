package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// DefaultHeadscalePort is the default HTTP port for the Headscale coordination server.
	DefaultHeadscalePort = 8080

	// DefaultTailscalePort is the default UDP listen port for tailscaled WireGuard traffic.
	DefaultTailscalePort = 41641
)

// HeadscaleOption configures a Headscale coordination server started on a Node.
type HeadscaleOption func(*headscaleConfig)

type headscaleConfig struct {
	serverAddr string
	port       int
	ipv4Prefix string
	ipv6Prefix string
	baseDomain string
}

// WithHeadscaleServerAddr sets the IPv4 address advertised by Headscale in its server_url
// and embedded DERP map. If unset, the Node's first attached network IPv4 address is used.
func WithHeadscaleServerAddr(addr string) HeadscaleOption {
	return func(c *headscaleConfig) {
		c.serverAddr = addr
	}
}

// WithHeadscalePort sets the HTTP port on which Headscale listens (defaults to 8080).
func WithHeadscalePort(port int) HeadscaleOption {
	return func(c *headscaleConfig) {
		c.port = port
	}
}

// WithHeadscaleIPv4Prefix overrides the tailnet IPv4 CGNAT prefix (defaults to "100.64.0.0/10").
func WithHeadscaleIPv4Prefix(cidr string) HeadscaleOption {
	return func(c *headscaleConfig) {
		c.ipv4Prefix = cidr
	}
}

// WithHeadscaleIPv6Prefix overrides the tailnet IPv6 ULA prefix (defaults to "fd7a:115c:a1e0::/48").
func WithHeadscaleIPv6Prefix(cidr string) HeadscaleOption {
	return func(c *headscaleConfig) {
		c.ipv6Prefix = cidr
	}
}

// WithHeadscaleBaseDomain overrides the MagicDNS base domain (defaults to "tailnet.local").
func WithHeadscaleBaseDomain(domain string) HeadscaleOption {
	return func(c *headscaleConfig) {
		c.baseDomain = domain
	}
}

// Headscale represents a running self-contained Headscale control plane and embedded DERP server on a Node.
type Headscale struct {
	node       *Node
	serverAddr string
	port       int
	configPath string
	socketPath string
	pidFile    string
	logFile    string

	mu      sync.Mutex
	stopped bool
}

// InstallHeadscale installs the headscale package inside an Alpine-based Node if not already present.
func (n *Node) InstallHeadscale(ctx context.Context) error {
	if n.t != nil {
		n.t.Helper()
	}

	installCmd := "command -v headscale >/dev/null 2>&1 || apk add --no-cache --no-scripts headscale"
	if out, err := n.Exec(ctx, []string{"sh", "-c", installCmd}); err != nil {
		return fmt.Errorf("install headscale on %s: %w (output: %s)", n.Name, err, out)
	}
	return nil
}

// StartHeadscale installs (if needed) and starts a self-contained Headscale coordination server
// with an embedded DERP/STUN server on the Node.
func (n *Node) StartHeadscale(ctx context.Context, opts ...HeadscaleOption) (*Headscale, error) {
	if n.t != nil {
		n.t.Helper()
	}

	if err := n.InstallHeadscale(ctx); err != nil {
		return nil, err
	}

	cfg := &headscaleConfig{
		port:       DefaultHeadscalePort,
		ipv4Prefix: "100.64.0.0/10",
		ipv6Prefix: "fd7a:115c:a1e0::/48",
		baseDomain: "tailnet.local",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	if cfg.serverAddr == "" {
		cfg.serverAddr = defaultNodeIP(n)
	}

	configPath := "/etc/headscale/config.yaml"
	socketPath := "/var/run/headscale/headscale.sock"
	pidFile := "/var/run/headscale.pid"
	logFile := "/var/log/headscale.log"

	configYAML := buildHeadscaleConfig(cfg, socketPath)

	startScript := fmt.Sprintf(
		"mkdir -p /etc/headscale /var/lib/headscale /var/run/headscale /var/log && "+
			"rm -f %s %s %s /var/lib/headscale/db.sqlite* && "+
			"cat <<'EOF' > %s\n%sEOF\n"+
			"headscale -c %s serve > %s 2>&1 &\n"+
			"echo $! > %s\n"+
			"for i in $(seq 1 100); do "+
			"  if [ -S %s ] && headscale -c %s users list >/dev/null 2>&1; then exit 0; fi; "+
			"  if ! kill -0 $(cat %s) 2>/dev/null; then cat %s >&2; exit 1; fi; "+
			"  sleep 0.05; "+
			"done; "+
			"cat %s >&2; exit 1",
		pidFile, socketPath, logFile,
		configPath, configYAML,
		configPath, logFile,
		pidFile,
		socketPath, configPath,
		pidFile, logFile,
		logFile,
	)

	if out, err := n.Exec(ctx, []string{"sh", "-c", startScript}); err != nil {
		return nil, fmt.Errorf("start headscale on %s: %w (output: %s)", n.Name, err, out)
	}

	hs := &Headscale{
		node:       n,
		serverAddr: cfg.serverAddr,
		port:       cfg.port,
		configPath: configPath,
		socketPath: socketPath,
		pidFile:    pidFile,
		logFile:    logFile,
	}

	if n.t != nil {
		n.t.Cleanup(func() {
			_ = hs.Stop(context.Background())
		})
	}

	return hs, nil
}

// URL returns the coordination server base URL used by Tailscale clients (--login-server).
func (h *Headscale) URL() string {
	return fmt.Sprintf("http://%s:%d", h.serverAddr, h.port)
}

// CreateUser creates a new user namespace in Headscale and returns its numeric user ID.
func (h *Headscale) CreateUser(ctx context.Context, username string) (uint64, error) {
	out, err := h.node.Exec(ctx, []string{
		"headscale", "-c", h.configPath, "users", "create", username, "-o", "json",
	})
	if err != nil {
		return 0, fmt.Errorf("create headscale user %q on %s: %w (output: %s)", username, h.node.Name, err, out)
	}

	var resp struct {
		ID uint64 `json:"id"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return 0, fmt.Errorf("parse headscale user create output on %s: %w (%s)", h.node.Name, err, out)
	}
	if resp.ID == 0 {
		return 0, fmt.Errorf("expected non-zero user ID from headscale on %s, got: %s", h.node.Name, out)
	}
	return resp.ID, nil
}

// CreatePreAuthKey generates a pre-authentication key for the given numeric Headscale user ID.
func (h *Headscale) CreatePreAuthKey(ctx context.Context, userID uint64, reusable bool, expiration string) (string, error) {
	if expiration == "" {
		expiration = "24h"
	}
	args := []string{
		"headscale", "-c", h.configPath,
		"preauthkeys", "create",
		"-u", fmt.Sprintf("%d", userID),
		"-e", expiration,
		"-o", "json",
	}
	if reusable {
		args = append(args, "--reusable")
	}

	out, err := h.node.Exec(ctx, args)
	if err != nil {
		return "", fmt.Errorf("create headscale preauthkey for user %d on %s: %w (output: %s)", userID, h.node.Name, err, out)
	}

	var resp struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal([]byte(out), &resp); err != nil {
		return "", fmt.Errorf("parse headscale preauthkey output on %s: %w (%s)", h.node.Name, err, out)
	}
	if resp.Key == "" {
		return "", fmt.Errorf("empty preauthkey returned by headscale on %s: %s", h.node.Name, out)
	}
	return resp.Key, nil
}

// CreateAuthKey is a convenience helper that creates the user namespace and returns a reusable pre-auth key.
func (h *Headscale) CreateAuthKey(ctx context.Context, username string) (string, error) {
	userID, err := h.CreateUser(ctx, username)
	if err != nil {
		return "", err
	}
	return h.CreatePreAuthKey(ctx, userID, true, "24h")
}

// Stop gracefully terminates the Headscale server inside the Node.
func (h *Headscale) Stop(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.stopped {
		return nil
	}

	stopScript := fmt.Sprintf(
		"if [ -f %s ]; then "+
			"  pid=$(cat %s); "+
			"  kill -TERM $pid 2>/dev/null || true; "+
			"  for i in $(seq 1 50); do "+
			"    kill -0 $pid 2>/dev/null || break; "+
			"    sleep 0.05; "+
			"  done; "+
			"fi",
		h.pidFile, h.pidFile,
	)
	if _, err := h.node.Exec(ctx, []string{"sh", "-c", stopScript}); err != nil {
		return fmt.Errorf("stop headscale on %s: %w", h.node.Name, err)
	}

	h.stopped = true
	return nil
}

func defaultNodeIP(n *Node) string {
	if len(n.IPs) == 0 {
		return "127.0.0.1"
	}
	keys := make([]string, 0, len(n.IPs))
	for k := range n.IPs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return n.IPs[keys[0]]
}

func buildHeadscaleConfig(cfg *headscaleConfig, socketPath string) string {
	return fmt.Sprintf(`---
server_url: http://%s:%d
listen_addr: 0.0.0.0:%d
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false
noise:
  private_key_path: /var/lib/headscale/noise_private.key
prefixes:
  v4: %s
  v6: %s
  allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: "headscale"
    region_name: "Headscale Embedded DERP"
    verify_clients: true
    stun_listen_addr: "0.0.0.0:3478"
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
    ipv4: %s
    ipv6: ::1
  urls: []
  paths: []
  auto_update_enabled: false
  update_frequency: 3h
disable_check_updates: true
ephemeral_node_inactivity_timeout: 30m
database:
  type: sqlite
  debug: false
  sqlite:
    path: /var/lib/headscale/db.sqlite
    write_ahead_log: true
log:
  level: info
  format: text
policy:
  mode: file
  path: ""
dns:
  magic_dns: true
  base_domain: %s
  override_local_dns: false
  nameservers:
    global: []
    split: {}
  search_domains: []
  extra_records: []
unix_socket: %s
unix_socket_permission: "0770"
logtail:
  enabled: false
randomize_client_port: false
`, cfg.serverAddr, cfg.port, cfg.port, cfg.ipv4Prefix, cfg.ipv6Prefix, cfg.serverAddr, cfg.baseDomain, socketPath)
}

// TailscaleOption configures a Tailscale daemon and client session on a Node.
type TailscaleOption func(*tailscaleConfig)

type tailscaleConfig struct {
	loginServer     string
	authKey         string
	hostname        string
	port            int
	iface           string
	acceptRoutes    bool
	advertiseRoutes []string
	extraUpArgs     []string
}

// WithLoginServer specifies the coordination server URL (e.g. hs.URL()).
func WithLoginServer(url string) TailscaleOption {
	return func(c *tailscaleConfig) {
		c.loginServer = url
	}
}

// WithAuthKey specifies the pre-authentication key used to register the Node with the tailnet.
func WithAuthKey(key string) TailscaleOption {
	return func(c *tailscaleConfig) {
		c.authKey = key
	}
}

// WithHostname overrides the Tailscale hostname registered for the Node (defaults to Node.Name).
func WithHostname(hostname string) TailscaleOption {
	return func(c *tailscaleConfig) {
		c.hostname = hostname
	}
}

// WithTailscalePort sets the UDP port used by tailscaled for WireGuard traffic (defaults to 41641).
func WithTailscalePort(port int) TailscaleOption {
	return func(c *tailscaleConfig) {
		c.port = port
	}
}

// WithTailscaleInterface overrides the TUN interface name created by tailscaled (defaults to "tailscale0").
func WithTailscaleInterface(iface string) TailscaleOption {
	return func(c *tailscaleConfig) {
		c.iface = iface
	}
}

// WithAcceptRoutes enables accepting subnet routes advertised by other tailnet nodes.
func WithAcceptRoutes(accept bool) TailscaleOption {
	return func(c *tailscaleConfig) {
		c.acceptRoutes = accept
	}
}

// WithAdvertiseRoutes configures CIDR routes advertised by this Node to the tailnet.
func WithAdvertiseRoutes(routes ...string) TailscaleOption {
	return func(c *tailscaleConfig) {
		c.advertiseRoutes = append(c.advertiseRoutes, routes...)
	}
}

// WithTailscaleExtraUpArgs appends custom CLI flags to `tailscale up`.
func WithTailscaleExtraUpArgs(args ...string) TailscaleOption {
	return func(c *tailscaleConfig) {
		c.extraUpArgs = append(c.extraUpArgs, args...)
	}
}

// TailscalePeerStatus holds status metadata for a node in `tailscale status --json`.
type TailscalePeerStatus struct {
	ID           string   `json:"ID"`
	PublicKey    string   `json:"PublicKey"`
	HostName     string   `json:"HostName"`
	DNSName      string   `json:"DNSName"`
	OS           string   `json:"OS"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Addrs        []string `json:"Addrs"`
	CurAddr      string   `json:"CurAddr"`
	Relay        string   `json:"Relay"`
	RxBytes      int64    `json:"RxBytes"`
	TxBytes      int64    `json:"TxBytes"`
	Online       bool     `json:"Online"`
	Active       bool     `json:"Active"`
}

// TailscaleStatus represents the decoded output of `tailscale status --json`.
type TailscaleStatus struct {
	Version      string                         `json:"Version"`
	TUN          bool                           `json:"TUN"`
	BackendState string                         `json:"BackendState"`
	TailscaleIPs []string                       `json:"TailscaleIPs"`
	Self         *TailscalePeerStatus           `json:"Self,omitempty"`
	Peer         map[string]TailscalePeerStatus `json:"Peer,omitempty"`
}

// Tailscale represents a running tailscaled instance inside a Node.
type Tailscale struct {
	node       *Node
	iface      string
	port       int
	socketPath string
	stateDir   string
	pidFile    string
	logFile    string
	IPv4Addr   string

	mu      sync.Mutex
	stopped bool
}

// InstallTailscale installs the tailscale package inside an Alpine-based Node if not already present.
func (n *Node) InstallTailscale(ctx context.Context) error {
	if n.t != nil {
		n.t.Helper()
	}

	installCmd := "(command -v tailscale >/dev/null 2>&1 && command -v tailscaled >/dev/null 2>&1) || apk add --no-cache --no-scripts tailscale"
	if out, err := n.Exec(ctx, []string{"sh", "-c", installCmd}); err != nil {
		return fmt.Errorf("install tailscale on %s: %w (output: %s)", n.Name, err, out)
	}
	return nil
}

// StartTailscale installs (if needed) and starts `tailscaled` inside the Node.
// If WithLoginServer or WithAuthKey is provided, it also runs `tailscale up` to join the tailnet
// and populates Tailscale.IPv4Addr with the assigned 100.64.x.y overlay IP.
func (n *Node) StartTailscale(ctx context.Context, opts ...TailscaleOption) (*Tailscale, error) {
	if n.t != nil {
		n.t.Helper()
	}

	if err := n.InstallTailscale(ctx); err != nil {
		return nil, err
	}

	cfg := &tailscaleConfig{
		hostname: n.Name,
		port:     DefaultTailscalePort,
		iface:    "tailscale0",
	}
	for _, opt := range opts {
		opt(cfg)
	}

	stateDir := "/var/lib/tailscale"
	socketPath := "/var/run/tailscale/tailscaled.sock"
	pidFile := "/var/run/tailscaled.pid"
	logFile := "/var/log/tailscaled.log"

	startScript := fmt.Sprintf(
		"mkdir -p %s /var/run/tailscale /var/log && "+
			"rm -f %s %s %s\n"+
			"tailscaled --statedir=%s --socket=%s --tun=%s --port=%d > %s 2>&1 &\n"+
			"echo $! > %s\n"+
			"for i in $(seq 1 100); do "+
			"  if [ -S %s ]; then exit 0; fi; "+
			"  if ! kill -0 $(cat %s) 2>/dev/null; then cat %s >&2; exit 1; fi; "+
			"  sleep 0.05; "+
			"done; "+
			"cat %s >&2; exit 1",
		stateDir,
		pidFile, socketPath, logFile,
		stateDir, socketPath, cfg.iface, cfg.port, logFile,
		pidFile,
		socketPath,
		pidFile, logFile,
		logFile,
	)

	if out, err := n.Exec(ctx, []string{"sh", "-c", startScript}); err != nil {
		return nil, fmt.Errorf("start tailscaled on %s: %w (output: %s)", n.Name, err, out)
	}

	ts := &Tailscale{
		node:       n,
		iface:      cfg.iface,
		port:       cfg.port,
		socketPath: socketPath,
		stateDir:   stateDir,
		pidFile:    pidFile,
		logFile:    logFile,
	}

	if n.t != nil {
		n.t.Cleanup(func() {
			_ = ts.Stop(context.Background())
		})
	}

	if cfg.loginServer != "" || cfg.authKey != "" {
		if err := ts.upWithConfig(ctx, cfg); err != nil {
			return nil, err
		}
	}

	return ts, nil
}

// Up runs `tailscale up` on a running Tailscale instance to authenticate and connect to the tailnet.
func (t *Tailscale) Up(ctx context.Context, opts ...TailscaleOption) error {
	cfg := &tailscaleConfig{
		hostname: t.node.Name,
		port:     t.port,
		iface:    t.iface,
	}
	for _, opt := range opts {
		opt(cfg)
	}
	return t.upWithConfig(ctx, cfg)
}

func (t *Tailscale) upWithConfig(ctx context.Context, cfg *tailscaleConfig) error {
	args := buildTailscaleUpArgs(t.socketPath, cfg)
	if out, err := t.node.Exec(ctx, args); err != nil {
		return fmt.Errorf("tailscale up on %s: %w (output: %s)", t.node.Name, err, out)
	}

	ip, err := t.IPv4(ctx)
	if err != nil {
		return err
	}
	t.IPv4Addr = ip
	return nil
}

func buildTailscaleUpArgs(socketPath string, cfg *tailscaleConfig) []string {
	args := []string{
		"tailscale",
		"--socket=" + socketPath,
		"up",
		"--netfilter-mode=off",
		"--accept-dns=false",
		"--timeout=30s",
	}
	if cfg.loginServer != "" {
		args = append(args, "--login-server="+cfg.loginServer)
	}
	if cfg.authKey != "" {
		args = append(args, "--auth-key="+cfg.authKey)
	}
	if cfg.hostname != "" {
		args = append(args, "--hostname="+cfg.hostname)
	}
	if cfg.acceptRoutes {
		args = append(args, "--accept-routes")
	}
	if len(cfg.advertiseRoutes) > 0 {
		args = append(args, "--advertise-routes="+strings.Join(cfg.advertiseRoutes, ","))
	}
	args = append(args, cfg.extraUpArgs...)
	return args
}

// IPv4 returns the Tailscale IPv4 address assigned to this Node (e.g. "100.64.0.1").
func (t *Tailscale) IPv4(ctx context.Context) (string, error) {
	out, err := t.node.Exec(ctx, []string{"tailscale", "--socket=" + t.socketPath, "ip", "-4"})
	if err != nil {
		return "", fmt.Errorf("query tailscale IPv4 on %s: %w (output: %s)", t.node.Name, err, out)
	}
	ip := strings.TrimSpace(strings.Split(out, "\n")[0])
	if ip == "" {
		return "", fmt.Errorf("empty tailscale IPv4 on %s", t.node.Name)
	}
	return ip, nil
}

// Status queries `tailscale status --json` and returns the decoded TailscaleStatus.
func (t *Tailscale) Status(ctx context.Context) (*TailscaleStatus, error) {
	out, err := t.node.Exec(ctx, []string{"tailscale", "--socket=" + t.socketPath, "status", "--json"})
	if err != nil {
		return nil, fmt.Errorf("query tailscale status on %s: %w (output: %s)", t.node.Name, err, out)
	}
	var st TailscaleStatus
	if err := json.Unmarshal([]byte(out), &st); err != nil {
		return nil, fmt.Errorf("unmarshal tailscale status on %s: %w", t.node.Name, err)
	}
	return &st, nil
}

// WaitForPeer polls `tailscale status --json` until a peer matching target (by HostName or TailscaleIP)
// is present and online in this Node's tailnet map.
func (t *Tailscale) WaitForPeer(ctx context.Context, target string) (*TailscalePeerStatus, error) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		st, err := t.Status(ctx)
		if err == nil && st.BackendState == "Running" {
			for _, peer := range st.Peer {
				if !peer.Online {
					continue
				}
				if peer.HostName == target {
					p := peer
					return &p, nil
				}
				for _, ip := range peer.TailscaleIPs {
					if ip == target {
						p := peer
						return &p, nil
					}
				}
			}
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("wait for tailscale peer %q on %s: %w", target, t.node.Name, ctx.Err())
		case <-ticker.C:
		}
	}
}

// Ping runs `tailscale ping` to probe Tailscale-level connectivity (disco / direct UDP / DERP) to target.
func (t *Tailscale) Ping(ctx context.Context, target string, count int) (string, error) {
	if count <= 0 {
		count = 1
	}
	return t.node.Exec(ctx, []string{
		"tailscale",
		"--socket=" + t.socketPath,
		"ping",
		fmt.Sprintf("--c=%d", count),
		"--timeout=5s",
		target,
	})
}

// Stop gracefully terminates the tailscaled daemon inside the Node.
func (t *Tailscale) Stop(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.stopped {
		return nil
	}

	stopScript := fmt.Sprintf(
		"if [ -f %s ]; then "+
			"  pid=$(cat %s); "+
			"  kill -TERM $pid 2>/dev/null || true; "+
			"  for i in $(seq 1 50); do "+
			"    kill -0 $pid 2>/dev/null || break; "+
			"    sleep 0.05; "+
			"  done; "+
			"fi",
		t.pidFile, t.pidFile,
	)
	if _, err := t.node.Exec(ctx, []string{"sh", "-c", stopScript}); err != nil {
		return fmt.Errorf("stop tailscaled on %s: %w", t.node.Name, err)
	}

	t.stopped = true
	return nil
}
