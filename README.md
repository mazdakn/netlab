# netlab

Automated Docker-based networking test lab in Go using `go test` and [`testcontainers-go`](https://github.com/testcontainers/testcontainers-go).

## Architecture

- **[`pkg/lab/lab.go`](file:///home/mazdak/src/netlab/pkg/lab/lab.go)**: Declarative test topology builder (`Lab`, `Network`, `Node`) with automatic `t.Cleanup()` lifecycle management, static IPAM subnet allocation, multi-homed gateway support, sysctl configuration (`net.ipv4.ip_forward=1`), and command execution helpers.
- **[`pkg/lab/pcap.go`](file:///home/mazdak/src/netlab/pkg/lab/pcap.go)** & **[`internal/pcapagent/main.go`](file:///home/mazdak/src/netlab/internal/pcapagent/main.go)**: Pure-Go packet capture and decoding powered by [`github.com/gopacket/gopacket`](https://github.com/gopacket/gopacket) (`pcapgo` + `AF_PACKET` sockets) with zero dependency on `tcpdump` or `libpcap`, returning typed `[]gopacket.Packet` layers (`layers.IPv4`, `layers.UDP`, `layers.ICMPv4`).
- **[`pkg/lab/wireguard.go`](file:///home/mazdak/src/netlab/pkg/lab/wireguard.go)** & **[`internal/wgagent/main.go`](file:///home/mazdak/src/netlab/internal/wgagent/main.go)**: Pure-Go userspace WireGuard tunnel setup powered by [`golang.zx2c4.com/wireguard`](https://pkg.go.dev/golang.zx2c4.com/wireguard) (`wireguard-go`) and its UAPI protocol (`SetupWireGuard`, `WireGuardStatus`), eliminating any dependency on kernel WireGuard or `wireguard-tools` (`wg`).
- **[`pkg/lab/suricata.go`](file:///home/mazdak/src/netlab/pkg/lab/suricata.go)**: On-demand Suricata installation (`InstallSuricata`), daemon lifecycle management (`StartSuricata`, `Stop`), and structured `eve.json` / `fast.log` alert inspection (`Alerts`, `EVEEvents`, `FastLog`).
- **[`pkg/lab/tailscale.go`](file:///home/mazdak/src/netlab/pkg/lab/tailscale.go)**: Self-contained Headscale control plane and embedded DERP/STUN setup (`InstallHeadscale`, `StartHeadscale`, `CreateAuthKey`) paired with Tailscale node lifecycle and status helpers (`InstallTailscale`, `StartTailscale`, `WaitForPeer`, `Status`, `Ping`).
- **[`scenarios/wireguard_gateway_test.go`](file:///home/mazdak/src/netlab/scenarios/wireguard_gateway_test.go)**: End-to-end test (`TestWireGuardPeersViaSuricata`) where two WireGuard peers on separate subnets (`172.28.10.0/24` and `172.28.20.0/24`) establish an encrypted tunnel (`10.100.0.0/24`) routed and inspected through an intermediate Suricata gateway container.
- **[`scenarios/tailscale_gateway_test.go`](file:///home/mazdak/src/netlab/scenarios/tailscale_gateway_test.go)**: End-to-end test (`TestTailscaleTailnetViaGateway`) where two Tailscale nodes on separate subnets (`172.28.10.0/24` and `172.28.20.0/24`) register with a local Headscale coordination server on the gateway (`172.28.10.254:8080`) and establish direct encrypted peer-to-peer connectivity (`100.64.0.1` <-> `100.64.0.2`) over `tailscale0`.

## Topology: WireGuard Peers Routed via Suricata Gateway

```text
+--------------------+          +-----------------------+          +--------------------+
|       peer-a       |          |   gateway (suricata)  |          |       peer-b       |
|                    |  net-a   |   (ip_forward = 1)    |  net-b   |                    |
| eth0: 172.28.10.10 +----------+ eth0: 172.28.10.254   |          |                    |
| wg0:  10.100.0.1   |          | eth1: 172.28.20.254   +----------+ eth0: 172.28.20.10 |
|                    |          |                       |          | wg0:  10.100.0.2   |
+--------------------+          +-----------------------+          +--------------------+
```

## Running Tests

```bash
# Run unit tests (no Docker required)
go test -v ./pkg/lab/...

# Run container networking scenarios (requires Docker daemon running)
go test -v ./scenarios/...
```
