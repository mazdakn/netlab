package scenarios

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
	"github.com/mazdak/netlab/pkg/lab"
)

// TestTailscaleTailnetViaGateway tests two Tailscale nodes on separate subnets (net-a and net-b)
// coordinated by a self-contained Headscale server running on an intermediate gateway container:
//
//	+--------------------+          +--------------------------+          +--------------------+
//	|       node-a       |          |    gateway (headscale)   |          |       node-b       |
//	|                    |  net-a   |     (ip_forward = 1)     |  net-b   |                    |
//	| eth0: 172.28.10.10 +----------+ eth0: 172.28.10.254      |          |                    |
//	| ts0:  100.64.0.1   |          | eth1: 172.28.20.254      +----------+ eth0: 172.28.20.10 |
//	|                    |          | headscale: :8080 / :3478 |          | ts0:  100.64.0.2   |
//	+--------------------+          +--------------------------+          +--------------------+
func TestTailscaleTailnetViaGateway(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
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

	// 3. Start node-a on net-a and node-b on net-b
	nodeA, err := topo.CreateNode(
		ctx,
		"node-a",
		lab.WithNetwork(netA, "172.28.10.10"),
	)
	if err != nil {
		t.Fatalf("create node-a: %v", err)
	}

	nodeB, err := topo.CreateNode(
		ctx,
		"node-b",
		lab.WithNetwork(netB, "172.28.20.10"),
	)
	if err != nil {
		t.Fatalf("create node-b: %v", err)
	}

	// 4. Configure static underlay routes on node-a and node-b via the gateway
	if err := nodeA.AddRoute(ctx, netB.Subnet, gateway.IPs[netA.Name]); err != nil {
		t.Fatalf("add static route on node-a: %v", err)
	}
	if err := nodeB.AddRoute(ctx, netA.Subnet, gateway.IPs[netB.Name]); err != nil {
		t.Fatalf("add static route on node-b: %v", err)
	}

	// Verify underlay reachability across the gateway before bringing up the tailnet
	if out, err := nodeA.Ping(ctx, nodeB.IPs[netB.Name], 2); err != nil {
		t.Fatalf("underlay ping from node-a to node-b failed: %v\n%s", err, out)
	}

	// 5. Install Headscale on the gateway and Tailscale on both nodes concurrently
	var installWG sync.WaitGroup
	errCh := make(chan error, 3)

	installWG.Add(3)
	go func() {
		defer installWG.Done()
		if err := gateway.InstallHeadscale(ctx); err != nil {
			errCh <- err
		}
	}()
	go func() {
		defer installWG.Done()
		if err := nodeA.InstallTailscale(ctx); err != nil {
			errCh <- err
		}
	}()
	go func() {
		defer installWG.Done()
		if err := nodeB.InstallTailscale(ctx); err != nil {
			errCh <- err
		}
	}()
	installWG.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("package installation failed: %v", err)
		}
	}

	// 6. Start the self-contained Headscale control plane on the gateway and create a reusable pre-auth key
	hs, err := gateway.StartHeadscale(
		ctx,
		lab.WithHeadscaleServerAddr(gateway.IPs[netA.Name]),
	)
	if err != nil {
		t.Fatalf("start headscale on gateway: %v", err)
	}

	authKey, err := hs.CreateAuthKey(ctx, "default")
	if err != nil {
		t.Fatalf("create headscale pre-auth key: %v", err)
	}

	// 7. Join node-a and node-b to the Headscale tailnet
	tsA, err := nodeA.StartTailscale(
		ctx,
		lab.WithLoginServer(hs.URL()),
		lab.WithAuthKey(authKey),
		lab.WithHostname("node-a"),
		lab.WithTailscalePort(lab.DefaultTailscalePort),
	)
	if err != nil {
		t.Fatalf("start tailscale on node-a: %v", err)
	}

	tsB, err := nodeB.StartTailscale(
		ctx,
		lab.WithLoginServer(hs.URL()),
		lab.WithAuthKey(authKey),
		lab.WithHostname("node-b"),
		lab.WithTailscalePort(lab.DefaultTailscalePort),
	)
	if err != nil {
		t.Fatalf("start tailscale on node-b: %v", err)
	}

	t.Logf("Tailscale overlay IPs assigned: node-a=%s, node-b=%s", tsA.IPv4Addr, tsB.IPv4Addr)
	if tsA.IPv4Addr != "100.64.0.1" || tsB.IPv4Addr != "100.64.0.2" {
		t.Fatalf("expected sequential tailnet IPs 100.64.0.1 and 100.64.0.2, got node-a=%s node-b=%s",
			tsA.IPv4Addr, tsB.IPv4Addr)
	}

	// Wait until both nodes see each other online in their tailnet peer map
	if _, err := tsA.WaitForPeer(ctx, tsB.IPv4Addr); err != nil {
		t.Fatalf("node-a waiting for peer node-b (%s): %v", tsB.IPv4Addr, err)
	}
	if _, err := tsB.WaitForPeer(ctx, tsA.IPv4Addr); err != nil {
		t.Fatalf("node-b waiting for peer node-a (%s): %v", tsA.IPv4Addr, err)
	}

	// 8. Start packet captures on gateway (underlay UDP:41641) and node-b (overlay tailscale0 ICMP)
	gwCapture, err := gateway.StartCapture(
		ctx,
		lab.WithInterface("any"),
		lab.WithBPFFilter("udp port 41641"),
		lab.WithSaveOnFailure("artifacts/pcap"),
	)
	if err != nil {
		t.Fatalf("start gateway packet capture: %v", err)
	}

	tsCapture, err := nodeB.StartCapture(
		ctx,
		lab.WithInterface("tailscale0"),
		lab.WithBPFFilter("icmp"),
		lab.WithSaveOnFailure("artifacts/pcap"),
	)
	if err != nil {
		t.Fatalf("start node-b tailscale0 packet capture: %v", err)
	}

	// 9. Probe Tailscale peer path and send ICMP echo traffic over the tailnet (100.64.0.1 -> 100.64.0.2)
	tsPingOutA, err := tsA.Ping(ctx, tsB.IPv4Addr, 1)
	if err != nil {
		t.Fatalf("tailscale ping from node-a to node-b failed: %v\n%s", err, tsPingOutA)
	}
	t.Logf("Tailscale ping (node-a -> node-b) output:\n%s", tsPingOutA)

	tsPingOutB, err := tsB.Ping(ctx, tsA.IPv4Addr, 1)
	if err != nil {
		t.Fatalf("tailscale ping from node-b to node-a failed: %v\n%s", err, tsPingOutB)
	}
	t.Logf("Tailscale ping (node-b -> node-a) output:\n%s", tsPingOutB)

	icmpPingOut, err := nodeA.Ping(ctx, tsB.IPv4Addr, 3)
	if err != nil {
		t.Fatalf("overlay ICMP ping over tailscale0 failed: %v\n%s", err, icmpPingOut)
	}
	t.Logf("Overlay ICMP ping output:\n%s", icmpPingOut)

	// 10. Stop captures and verify both encrypted underlay UDP:41641 and decrypted overlay ICMPv4 packets
	if err := gwCapture.Stop(ctx); err != nil {
		t.Fatalf("stop gateway packet capture: %v", err)
	}
	if err := tsCapture.Stop(ctx); err != nil {
		t.Fatalf("stop node-b tailscale0 packet capture: %v", err)
	}

	gwPackets, err := gwCapture.Packets(ctx)
	if err != nil {
		t.Fatalf("decode gateway captured packets: %v", err)
	}
	gwSummary, _ := gwCapture.DumpText(ctx)
	t.Logf("Gateway captured %d encrypted Tailscale UDP:41641 packets (gopacket):\n%s", len(gwPackets), gwSummary)
	if len(gwPackets) == 0 {
		t.Fatalf("expected gateway to capture UDP:41641 packets, got 0")
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
			uint16(udp.SrcPort) == lab.DefaultTailscalePort && uint16(udp.DstPort) == lab.DefaultTailscalePort {
			foundAtoB = true
			break
		}
	}
	if !foundAtoB {
		t.Fatalf("expected UDP packet from 172.28.10.10:41641 to 172.28.20.10:41641 in gateway capture")
	}

	tsPackets, err := tsCapture.Packets(ctx)
	if err != nil {
		t.Fatalf("decode node-b tailscale0 captured packets: %v", err)
	}
	tsSummary, _ := tsCapture.DumpText(ctx)
	t.Logf("node-b tailscale0 captured %d decrypted ICMPv4 packets (gopacket):\n%s", len(tsPackets), tsSummary)

	var echoRequests, echoReplies int
	for _, pkt := range tsPackets {
		ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			continue
		}
		icmp4, ok := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4)
		if !ok {
			continue
		}
		if ip4.SrcIP.String() == tsA.IPv4Addr && ip4.DstIP.String() == tsB.IPv4Addr &&
			icmp4.TypeCode.Type() == layers.ICMPv4TypeEchoRequest {
			echoRequests++
		}
		if ip4.SrcIP.String() == tsB.IPv4Addr && ip4.DstIP.String() == tsA.IPv4Addr &&
			icmp4.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
			echoReplies++
		}
	}
	if echoRequests < 3 || echoReplies < 3 {
		t.Fatalf("expected at least 3 ICMPv4 EchoRequests and 3 EchoReplies on tailscale0, got requests=%d replies=%d",
			echoRequests, echoReplies)
	}

	// 11. Verify Tailscale status and peer transfer counters on node-a
	statusA, err := tsA.Status(ctx)
	if err != nil {
		t.Fatalf("query tailscale status on node-a: %v", err)
	}
	if statusA.BackendState != "Running" {
		t.Fatalf("expected node-a BackendState=Running, got %q", statusA.BackendState)
	}

	foundPeerB := false
	for _, peer := range statusA.Peer {
		if peer.HostName == "node-b" {
			foundPeerB = true
			t.Logf("node-a peer status for node-b: CurAddr=%s Relay=%s RxBytes=%d TxBytes=%d",
				peer.CurAddr, peer.Relay, peer.RxBytes, peer.TxBytes)
			if peer.RxBytes <= 0 || peer.TxBytes <= 0 {
				t.Fatalf("expected positive RxBytes and TxBytes for peer node-b, got rx=%d tx=%d",
					peer.RxBytes, peer.TxBytes)
			}
		}
	}
	if !foundPeerB {
		t.Fatalf("expected peer node-b in node-a tailscale status")
	}
}
