# netlab

Automated Docker-based networking test lab in Go using `go test` and [`testcontainers-go`](https://github.com/testcontainers/testcontainers-go).

## Architecture

- **[`pkg/lab/lab.go`](file:///home/mazdak/src/netlab/pkg/lab/lab.go)**: Declarative test topology builder (`Lab`, `Network`, `Node`) with automatic `t.Cleanup()` lifecycle management, static IPAM subnet allocation, multi-homed gateway support, sysctl configuration (`net.ipv4.ip_forward=1`), and command execution helpers.
- **[`pkg/lab/pcap.go`](file:///home/mazdak/src/netlab/pkg/lab/pcap.go)** & **[`internal/pcapagent/main.go`](file:///home/mazdak/src/netlab/internal/pcapagent/main.go)**: Pure-Go packet capture and decoding powered by [`github.com/gopacket/gopacket`](https://github.com/gopacket/gopacket) (`pcapgo` + `AF_PACKET` sockets) with zero dependency on `tcpdump` or `libpcap`, returning typed `[]gopacket.Packet` layers (`layers.IPv4`, `layers.UDP`, `layers.ICMPv4`).
- **[`pkg/lab/wireguard.go`](file:///home/mazdak/src/netlab/pkg/lab/wireguard.go)** & **[`internal/wgagent/main.go`](file:///home/mazdak/src/netlab/internal/wgagent/main.go)**: Pure-Go userspace WireGuard tunnel setup powered by [`golang.zx2c4.com/wireguard`](https://pkg.go.dev/golang.zx2c4.com/wireguard) (`wireguard-go`) and its UAPI protocol (`SetupWireGuard`, `WireGuardStatus`), eliminating any dependency on kernel WireGuard or `wireguard-tools` (`wg`).
- **[`scenarios/wireguard_gateway_test.go`](file:///home/mazdak/src/netlab/scenarios/wireguard_gateway_test.go)**: End-to-end test where two WireGuard peers on separate subnets (`172.28.10.0/24` and `172.28.20.0/24`) establish an encrypted tunnel (`10.100.0.0/24`) routed through an intermediate gateway container.

## Topology: WireGuard Peers Routed via Gateway

```text
+--------------------+          +-----------------------+          +--------------------+
|       peer-a       |          |        gateway        |          |       peer-b       |
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
