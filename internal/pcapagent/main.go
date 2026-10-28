//go:build linux

package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/endian"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"golang.org/x/sys/unix"
)

func main() {
	iface := flag.String("iface", "any", "interface to capture on (or 'any')")
	outPath := flag.String("out", "/tmp/capture.pcap", "output pcap file path")
	readyPath := flag.String("ready", "", "file created once socket is listening")
	snapLen := flag.Int("snaplen", 65535, "snapshot length")
	maxPackets := flag.Int("c", 0, "stop after capturing N packets (0 = unlimited)")
	filterExpr := flag.String("filter", "", "packet filter expression (e.g. 'icmp', 'udp port 51820')")
	flag.Parse()

	matcher, err := parseFilter(*filterExpr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid filter %q: %v\n", *filterExpr, err)
		os.Exit(1)
	}

	outFile, err := os.Create(*outPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create pcap %s: %v\n", *outPath, err)
		os.Exit(1)
	}
	defer outFile.Close()

	// Determine whether to use EthernetHandle (L2 Ethernet) or SOCK_DGRAM (L3 Raw IP for 'any' or tunnel interfaces like wg0)
	useEthernet := false
	var netIface *net.Interface
	if *iface != "any" {
		netIface, err = net.InterfaceByName(*iface)
		if err != nil {
			fmt.Fprintf(os.Stderr, "interface %s: %v\n", *iface, err)
			os.Exit(1)
		}
		if len(netIface.HardwareAddr) > 0 && (netIface.Flags&net.FlagLoopback) == 0 {
			useEthernet = true
		}
	}

	pcapWriter := pcapgo.NewWriter(outFile)
	linkType := layers.LinkTypeRaw
	if useEthernet {
		linkType = layers.LinkTypeEthernet
	}
	if err := pcapWriter.WriteFileHeader(uint32(*snapLen), linkType); err != nil {
		fmt.Fprintf(os.Stderr, "write pcap header: %v\n", err)
		os.Exit(1)
	}
	_ = outFile.Sync()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	if useEthernet {
		if err := captureEthernet(*iface, *snapLen, *maxPackets, *readyPath, matcher, pcapWriter, outFile, sigCh); err != nil {
			fmt.Fprintf(os.Stderr, "capture ethernet: %v\n", err)
			os.Exit(1)
		}
		return
	}

	ifIndex := 0
	if netIface != nil {
		ifIndex = netIface.Index
	}
	if err := captureRawIP(ifIndex, *snapLen, *maxPackets, *readyPath, matcher, pcapWriter, outFile, sigCh); err != nil {
		fmt.Fprintf(os.Stderr, "capture raw ip: %v\n", err)
		os.Exit(1)
	}
}

func markReady(readyPath string) error {
	if readyPath == "" {
		return nil
	}
	return os.WriteFile(readyPath, []byte("ready\n"), 0o644)
}

func captureEthernet(
	iface string,
	snapLen int,
	maxPackets int,
	readyPath string,
	matcher packetMatcher,
	pcapWriter *pcapgo.Writer,
	outFile *os.File,
	sigCh <-chan os.Signal,
) error {
	handle, err := pcapgo.NewEthernetHandle(iface)
	if err != nil {
		return err
	}
	if err := handle.SetCaptureLength(snapLen); err != nil {
		_ = handle.Close()
		return err
	}
	if err := markReady(readyPath); err != nil {
		_ = handle.Close()
		return err
	}

	go func() {
		<-sigCh
		_ = handle.Close()
	}()

	captured := 0
	for {
		data, ci, err := handle.ReadPacketData()
		if err != nil {
			break
		}
		if matcher != nil {
			pkt := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.Lazy)
			if !matcher(pkt) {
				continue
			}
		}
		if err := pcapWriter.WritePacket(ci, data); err != nil {
			return err
		}
		_ = outFile.Sync()
		captured++
		if maxPackets > 0 && captured >= maxPackets {
			break
		}
	}
	return nil
}

func captureRawIP(
	ifIndex int,
	snapLen int,
	maxPackets int,
	readyPath string,
	matcher packetMatcher,
	pcapWriter *pcapgo.Writer,
	outFile *os.File,
	sigCh <-chan os.Signal,
) error {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, int(endian.Htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("open AF_PACKET SOCK_DGRAM: %w", err)
	}

	if ifIndex > 0 {
		addr := unix.SockaddrLinklayer{
			Protocol: endian.Htons(unix.ETH_P_ALL),
			Ifindex:  ifIndex,
		}
		if err := unix.Bind(fd, &addr); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("bind ifindex %d: %w", ifIndex, err)
		}
	}

	file := os.NewFile(uintptr(fd), "afpacket-dgram")
	defer file.Close()

	rawConn, err := file.SyscallConn()
	if err != nil {
		return err
	}

	if err := markReady(readyPath); err != nil {
		return err
	}

	go func() {
		<-sigCh
		_ = file.SetReadDeadline(time.Now())
		_ = file.Close()
	}()

	buf := make([]byte, snapLen)
	captured := 0

	for {
		var n int
		var recvErr error
		readErr := rawConn.Read(func(sfd uintptr) bool {
			n, _, recvErr = unix.Recvfrom(int(sfd), buf, 0)
			if recvErr == unix.EAGAIN || recvErr == unix.EWOULDBLOCK {
				return false
			}
			return true
		})
		if readErr != nil || recvErr != nil {
			break
		}
		if n <= 0 {
			continue
		}

		// Ensure packet is IPv4 or IPv6 for LinkTypeRaw
		version := buf[0] >> 4
		var firstLayer gopacket.LayerType
		switch version {
		case 4:
			firstLayer = layers.LayerTypeIPv4
		case 6:
			firstLayer = layers.LayerTypeIPv6
		default:
			continue
		}

		pktData := buf[:n]
		if matcher != nil {
			pkt := gopacket.NewPacket(pktData, firstLayer, gopacket.Lazy)
			if !matcher(pkt) {
				continue
			}
		}

		ci := gopacket.CaptureInfo{
			Timestamp:     time.Now(),
			CaptureLength: len(pktData),
			Length:        len(pktData),
		}
		if err := pcapWriter.WritePacket(ci, pktData); err != nil {
			return err
		}
		_ = outFile.Sync()
		captured++
		if maxPackets > 0 && captured >= maxPackets {
			break
		}
	}
	return nil
}

type packetMatcher func(gopacket.Packet) bool

// parseFilter supports common BPF-style filter expressions in pure Go using gopacket layers:
//   - "" (match all)
//   - "icmp"
//   - "udp" / "tcp"
//   - "port <N>" / "udp port <N>" / "tcp port <N>"
//   - "host <IP>"
func parseFilter(expr string) (packetMatcher, error) {
	expr = strings.TrimSpace(strings.ToLower(expr))
	if expr == "" {
		return nil, nil
	}

	tokens := strings.Fields(expr)
	switch {
	case len(tokens) == 1 && tokens[0] == "icmp":
		return func(p gopacket.Packet) bool {
			return p.Layer(layers.LayerTypeICMPv4) != nil || p.Layer(layers.LayerTypeICMPv6) != nil
		}, nil

	case len(tokens) == 1 && tokens[0] == "udp":
		return func(p gopacket.Packet) bool {
			return p.Layer(layers.LayerTypeUDP) != nil
		}, nil

	case len(tokens) == 1 && tokens[0] == "tcp":
		return func(p gopacket.Packet) bool {
			return p.Layer(layers.LayerTypeTCP) != nil
		}, nil

	case len(tokens) == 2 && tokens[0] == "port":
		port, err := strconv.Atoi(tokens[1])
		if err != nil {
			return nil, err
		}
		return func(p gopacket.Packet) bool {
			return matchPort(p, uint16(port), true, true)
		}, nil

	case len(tokens) == 3 && (tokens[0] == "udp" || tokens[0] == "tcp") && tokens[1] == "port":
		port, err := strconv.Atoi(tokens[2])
		if err != nil {
			return nil, err
		}
		wantUDP := tokens[0] == "udp"
		wantTCP := tokens[0] == "tcp"
		return func(p gopacket.Packet) bool {
			return matchPort(p, uint16(port), wantUDP, wantTCP)
		}, nil

	case len(tokens) == 2 && tokens[0] == "host":
		targetIP := net.ParseIP(tokens[1])
		if targetIP == nil {
			return nil, fmt.Errorf("invalid IP %q", tokens[1])
		}
		return func(p gopacket.Packet) bool {
			if ip4, ok := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
				return ip4.SrcIP.Equal(targetIP) || ip4.DstIP.Equal(targetIP)
			}
			if ip6, ok := p.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
				return ip6.SrcIP.Equal(targetIP) || ip6.DstIP.Equal(targetIP)
			}
			return false
		}, nil

	default:
		return nil, fmt.Errorf("unsupported filter expression %q", expr)
	}
}

func matchPort(p gopacket.Packet, port uint16, checkUDP, checkTCP bool) bool {
	if checkUDP {
		if udp, ok := p.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
			if uint16(udp.SrcPort) == port || uint16(udp.DstPort) == port {
				return true
			}
		}
	}
	if checkTCP {
		if tcp, ok := p.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
			if uint16(tcp.SrcPort) == port || uint16(tcp.DstPort) == port {
				return true
			}
		}
	}
	return false
}
