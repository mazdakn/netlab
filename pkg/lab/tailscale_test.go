package lab

import (
	"slices"
	"strings"
	"testing"
)

func TestBuildHeadscaleConfig(t *testing.T) {
	cfg := &headscaleConfig{
		serverAddr: "172.28.10.254",
		port:       DefaultHeadscalePort,
		ipv4Prefix: "100.64.0.0/10",
		ipv6Prefix: "fd7a:115c:a1e0::/48",
		baseDomain: "tailnet.local",
	}
	WithHeadscalePort(8081)(cfg)
	WithHeadscaleBaseDomain("lab.internal")(cfg)

	yaml := buildHeadscaleConfig(cfg, "/var/run/headscale/headscale.sock")

	expectedSnippets := []string{
		"server_url: http://172.28.10.254:8081",
		"listen_addr: 0.0.0.0:8081",
		"v4: 100.64.0.0/10",
		"ipv4: 172.28.10.254",
		"base_domain: lab.internal",
		"unix_socket: /var/run/headscale/headscale.sock",
	}
	for _, snippet := range expectedSnippets {
		if !strings.Contains(yaml, snippet) {
			t.Fatalf("expected headscale config to contain %q, got:\n%s", snippet, yaml)
		}
	}
}

func TestBuildTailscaleUpArgs(t *testing.T) {
	cfg := &tailscaleConfig{
		hostname: "node-a",
		port:     DefaultTailscalePort,
		iface:    "tailscale0",
	}
	for _, opt := range []TailscaleOption{
		WithLoginServer("http://172.28.10.254:8080"),
		WithAuthKey("secret-preauth-key"),
		WithHostname("ts-node-a"),
		WithAcceptRoutes(true),
		WithAdvertiseRoutes("172.28.10.0/24", "10.0.0.0/24"),
	} {
		opt(cfg)
	}

	args := buildTailscaleUpArgs("/var/run/tailscale/tailscaled.sock", cfg)

	expected := []string{
		"tailscale",
		"--socket=/var/run/tailscale/tailscaled.sock",
		"up",
		"--netfilter-mode=off",
		"--accept-dns=false",
		"--timeout=30s",
		"--login-server=http://172.28.10.254:8080",
		"--auth-key=secret-preauth-key",
		"--hostname=ts-node-a",
		"--accept-routes",
		"--advertise-routes=172.28.10.0/24,10.0.0.0/24",
	}
	if !slices.Equal(args, expected) {
		t.Fatalf("buildTailscaleUpArgs() = %v, want %v", args, expected)
	}
}
