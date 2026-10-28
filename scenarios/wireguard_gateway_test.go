package scenarios

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
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

	// 6. Start pure-Go gopacket/pcapgo captures on the gateway (underlay UDP:51820) and peer-b (overlay wg0 ICMP)
	gwCapture, err := gateway.StartCapture(
		ctx,
		lab.WithInterface("any"),
		lab.WithBPFFilter("udp port 51820"),
		lab.WithSaveOnFailure("artifacts/pcap"),
	)
	if err != nil {
		t.Fatalf("start gateway packet capture: %v", err)
	}

	wgCapture, err := peerB.StartCapture(
		ctx,
		lab.WithInterface("wg0"),
		lab.WithBPFFilter("icmp"),
		lab.WithSaveOnFailure("artifacts/pcap"),
	)
	if err != nil {
		t.Fatalf("start peer-b wg0 packet capture: %v", err)
	}

	// 7. Send traffic over the WireGuard tunnel (10.100.0.1 -> 10.100.0.2)
	pingOut, err := peerA.Ping(ctx, "10.100.0.2", 3)
	if err != nil {
		t.Fatalf("overlay ping over wireguard tunnel failed: %v\n%s", err, pingOut)
	}
	t.Logf("Overlay ping output:\n%s", pingOut)

	// 8. Stop captures and inspect decoded gopacket.Packet layers
	if err := gwCapture.Stop(ctx); err != nil {
		t.Fatalf("stop gateway packet capture: %v", err)
	}
	if err := wgCapture.Stop(ctx); err != nil {
		t.Fatalf("stop peer-b wg0 packet capture: %v", err)
	}

	gwPackets, err := gwCapture.Packets(ctx)
	if err != nil {
		t.Fatalf("decode gateway captured packets: %v", err)
	}
	gwSummary, _ := gwCapture.DumpText(ctx)
	t.Logf("Gateway captured %d encrypted UDP:51820 packets (gopacket):\n%s", len(gwPackets), gwSummary)
	if len(gwPackets) == 0 {
		t.Fatalf("expected gateway to capture UDP:51820 packets, got 0")
	}

	foundAtoB := false
	for _, pkt := range gwPackets {
		ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			continue
		}
		udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok {
			continue
		}
		if ip4.SrcIP.String() == "172.28.10.10" && ip4.DstIP.String() == "172.28.20.10" &&
			uint16(udp.SrcPort) == 51820 && uint16(udp.DstPort) == 51820 {
			foundAtoB = true
		}
	}
	if !foundAtoB {
		t.Fatalf("expected gopacket UDP layer from 172.28.10.10:51820 to 172.28.20.10:51820 in gateway capture")
	}

	wgPackets, err := wgCapture.Packets(ctx)
	if err != nil {
		t.Fatalf("decode peer-b wg0 captured packets: %v", err)
	}
	wgSummary, _ := wgCapture.DumpText(ctx)
	t.Logf("peer-b wg0 captured %d decrypted ICMPv4 packets (gopacket):\n%s", len(wgPackets), wgSummary)

	var echoRequests, echoReplies int
	for _, pkt := range wgPackets {
		ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			continue
		}
		icmp4, ok := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if !ok {
			continue
		}
		if ip4.SrcIP.String() == "10.100.0.1" && ip4.DstIP.String() == "10.100.0.2" &&
			icmp4.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
			echoRequests++
		}
		if ip4.SrcIP.String() == "10.100.0.2" && ip4.DstIP.String() == "10.100.0.1" &&
			icmp4.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
			echoReplies++
		}
	}
	if echoRequests < 3 || echoReplies < 3 {
		t.Fatalf("expected at least 3 ICMPv4 EchoRequests and 3 EchoReplies on wg0, got requests=%d replies=%d",
			echoRequests, echoReplies)
	}

	// Verify SaveToFile exports a valid non-empty .pcap file to the host
	pcapFile := filepath.Join(t.TempDir(), "gateway-wg.pcap")
	if err := gwCapture.SaveToFile(ctx, pcapFile); err != nil {
		t.Fatalf("save gateway pcap to file: %v", err)
	}
	if info, err := os.Stat(pcapFile); err != nil || info.Size() <= 24 {
		t.Fatalf("expected exported pcap file > 24 bytes (pcap global header), got info=%v err=%v", info, err)
	}

	// 9. Verify wireguard-go UAPI handshake and transfer stats on peer-a (without wg-tools)
	wgStatus, err := peerA.WireGuardStatus(ctx, "wg0")
	if err != nil {
		t.Fatalf("inspect wireguard-go UAPI status on peer-a: %v", err)
	}
	t.Logf("peer-a wg0 UAPI status:\n%s", wgStatus)
	if !strings.Contains(wgStatus, "last_handshake_time_sec=") || strings.Contains(wgStatus, "last_handshake_time_sec=0") {
		t.Fatalf("expected non-zero last_handshake_time_sec in UAPI status, got:\n%s", wgStatus)
	}

	// 10. Verify the gateway actually forwarded the encrypted UDP:51820 packets
	fwdStats, err := gateway.Exec(ctx, []string{"iptables", "-L", "FORWARD", "-v", "-n", "-x"})
	if err != nil {
		t.Fatalf("inspect gateway FORWARD counters: %v", err)
	}
	t.Logf("gateway FORWARD counters:\n%s", fwdStats)
	if !strings.Contains(fwdStats, "udp dpt:51820") || strings.Contains(fwdStats, "0        0 ACCEPT     udp") {
		t.Fatalf("expected non-zero UDP:51820 packets forwarded by gateway, got:\n%s", fwdStats)
	}
}
