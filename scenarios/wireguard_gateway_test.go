package scenarios

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/mazdak/netlab/pkg/lab"
)

// TestWireGuardPeersViaGateway tests two WireGuard peers on separate subnets (net-a and net-b)
// whose encrypted underlay UDP traffic is routed through an intermediate gateway container:
//
//	+--------------------+          +-----------------------+          +--------------------+
//	|       peer-a       |          |        gateway        |          |       peer-b       |
//	|                    |  net-a   |   (ip_forward = 1)    |  net-b   |                    |
//	| eth0: 172.28.10.10 +----------+ eth0: 172.28.10.254   |          |                    |
//	| wg0:  10.100.0.1   |          | eth1: 172.28.20.254   +----------+ eth0: 172.28.20.10 |
//	|                    |          |                       |          | wg0:  10.100.0.2   |
//	+--------------------+          +-----------------------+          +--------------------+
func TestWireGuardPeersViaGateway(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	topo := lab.New(t)

	// 1. Create two isolated underlay networks
	netA, err := topo.CreateNetwork(ctx, "net-a", "172.28.10.0/24", "172.28.10.1")
	if err != nil {
		t.Fatalf("create net-a: %v", err)
	}
	netB, err := topo.CreateNetwork(ctx, "net-b", "172.28.20.0/24", "172.28.20.1")
	if err != nil {
		t.Fatalf("create net-b: %v", err)
	}

	// 2. Start the intermediate gateway node connected to both net-a and net-b
	gateway, err := topo.CreateNode(
		ctx,
		"gateway",
		lab.WithNetwork(netA, "172.28.10.254"),
		lab.WithNetwork(netB, "172.28.20.254"),
		lab.WithIPForwarding(),
	)
	if err != nil {
		t.Fatalf("create gateway node: %v", err)
	}

	// Add an iptables rule on the gateway FORWARD chain to count UDP:51820 (WireGuard) packets
	if _, err := gateway.Exec(ctx, []string{
		"iptables", "-I", "FORWARD", "1", "-p", "udp", "--dport", "51820", "-j", "ACCEPT",
	}); err != nil {
		t.Fatalf("configure gateway iptables counter: %v", err)
	}

	// 3. Start peer-a on net-a and peer-b on net-b
	peerA, err := topo.CreateNode(
		ctx,
		"peer-a",
		lab.WithNetwork(netA, "172.28.10.10"),
	)
	if err != nil {
		t.Fatalf("create peer-a node: %v", err)
	}

	peerB, err := topo.CreateNode(
		ctx,
		"peer-b",
		lab.WithNetwork(netB, "172.28.20.10"),
	)
	if err != nil {
		t.Fatalf("create peer-b node: %v", err)
	}

	// 4. Configure static underlay routes on peer-a and peer-b via the gateway
	if err := peerA.AddRoute(ctx, netB.Subnet, gateway.IPs[netA.Name]); err != nil {
		t.Fatalf("add static route on peer-a: %v", err)
	}
	if err := peerB.AddRoute(ctx, netA.Subnet, gateway.IPs[netB.Name]); err != nil {
		t.Fatalf("add static route on peer-b: %v", err)
	}

	// Verify underlay reachability across the gateway before bringing up WireGuard
	if out, err := peerA.Ping(ctx, peerB.IPs[netB.Name], 2); err != nil {
		t.Fatalf("underlay ping from peer-a to peer-b failed: %v\n%s", err, out)
	}

	// 5. Generate WireGuard key pairs and configure wg0 on both peers
	keyA, err := lab.GenerateWGKeyPair()
	if err != nil {
		t.Fatalf("generate key pair for peer-a: %v", err)
	}
	keyB, err := lab.GenerateWGKeyPair()
	if err != nil {
		t.Fatalf("generate key pair for peer-b: %v", err)
	}

	err = peerA.SetupWireGuard(ctx, lab.WGInterfaceConfig{
		Interface:  "wg0",
		Address:    "10.100.0.1/24",
		PrivateKey: keyA.PrivateKey,
		ListenPort: 51820,
		Peers: []lab.WGPeerConfig{
			{
				PublicKey:  keyB.PublicKey,
				Endpoint:   "172.28.20.10:51820",
				AllowedIPs: []string{"10.100.0.2/32"},
			},
		},
	})
	if err != nil {
		t.Fatalf("setup wireguard on peer-a: %v", err)
	}

	err = peerB.SetupWireGuard(ctx, lab.WGInterfaceConfig{
		Interface:  "wg0",
		Address:    "10.100.0.2/24",
		PrivateKey: keyB.PrivateKey,
		ListenPort: 51820,
		Peers: []lab.WGPeerConfig{
			{
				PublicKey:  keyA.PublicKey,
				Endpoint:   "172.28.10.10:51820",
				AllowedIPs: []string{"10.100.0.1/32"},
			},
		},
	})
	if err != nil {
		t.Fatalf("setup wireguard on peer-b: %v", err)
	}

	// 6. Send traffic over the WireGuard tunnel (10.100.0.1 -> 10.100.0.2)
	pingOut, err := peerA.Ping(ctx, "10.100.0.2", 3)
	if err != nil {
		t.Fatalf("overlay ping over wireguard tunnel failed: %v\n%s", err, pingOut)
	}
	t.Logf("Overlay ping output:\n%s", pingOut)

	// 7. Verify WireGuard handshake and transfer stats on peer-a
	wgStatus, err := peerA.Exec(ctx, []string{"wg", "show", "wg0"})
	if err != nil {
		t.Fatalf("inspect wg0 on peer-a: %v", err)
	}
	t.Logf("peer-a wg0 status:\n%s", wgStatus)
	if !strings.Contains(wgStatus, "latest handshake") {
		t.Fatalf("expected active WireGuard handshake in `wg show wg0`, got:\n%s", wgStatus)
	}

	// 8. Verify the gateway actually forwarded the encrypted UDP:51820 packets
	fwdStats, err := gateway.Exec(ctx, []string{"iptables", "-L", "FORWARD", "-v", "-n", "-x"})
	if err != nil {
		t.Fatalf("inspect gateway FORWARD counters: %v", err)
	}
	t.Logf("gateway FORWARD counters:\n%s", fwdStats)
	if !strings.Contains(fwdStats, "udp dpt:51820") || strings.Contains(fwdStats, "0        0 ACCEPT     udp") {
		t.Fatalf("expected non-zero UDP:51820 packets forwarded by gateway, got:\n%s", fwdStats)
	}
}
