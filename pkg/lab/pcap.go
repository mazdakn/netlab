package lab

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

var (
	captureCounter uint64
	agentBuildOnce sync.Once
	agentBinPath   string
	agentBuildErr  error
)

const containerAgentPath = "/tmp/netlab-pcap-agent"

// buildPcapAgent compiles the static pure-Go pcapagent binary once per test process.
func buildPcapAgent() (string, error) {
	agentBuildOnce.Do(func() {
		_, thisFile, _, _ := runtime.Caller(0)
		repoRoot := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))
		agentSrc := filepath.Join(repoRoot, "internal", "pcapagent")

		tmpFile, err := os.CreateTemp("", "netlab-pcap-agent-*")
		if err != nil {
			agentBuildErr = fmt.Errorf("create temp agent binary: %w", err)
			return
		}
		_ = tmpFile.Close()
		agentBinPath = tmpFile.Name()

		cmd := exec.Command("go", "build", "-o", agentBinPath, agentSrc)
		cmd.Dir = repoRoot
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux")
		if out, err := cmd.CombinedOutput(); err != nil {
			agentBuildErr = fmt.Errorf("compile pcapagent: %w (%s)", err, strings.TrimSpace(string(out)))
			return
		}
	})
	return agentBinPath, agentBuildErr
}

// CaptureOption configures a PacketCapture started on a Node.
type CaptureOption func(*captureConfig)

type captureConfig struct {
	iface         string
	bpfFilter     string
	packetFilter  func(gopacket.Packet) bool
	snapLen       int
	maxPackets    int
	saveDir       string
	saveOnFailure bool
	saveAlways    bool
}

// WithInterface specifies the network interface to capture on (defaults to "any").
func WithInterface(iface string) CaptureOption {
	return func(c *captureConfig) {
		c.iface = iface
	}
}

// WithBPFFilter sets a filter expression evaluated by the pure-Go capture agent
// (e.g. "udp port 51820", "icmp", "udp", "tcp", "host 10.100.0.1").
func WithBPFFilter(filter string) CaptureOption {
	return func(c *captureConfig) {
		c.bpfFilter = filter
	}
}

// WithPacketFilter sets a custom Go predicate function to filter decoded gopacket.Packet objects.
func WithPacketFilter(fn func(gopacket.Packet) bool) CaptureOption {
	return func(c *captureConfig) {
		c.packetFilter = fn
	}
}

// WithSnapLen sets the snapshot length in bytes for captured packets.
func WithSnapLen(bytes int) CaptureOption {
	return func(c *captureConfig) {
		c.snapLen = bytes
	}
}

// WithMaxPackets stops the capture automatically after capturing count packets.
func WithMaxPackets(count int) CaptureOption {
	return func(c *captureConfig) {
		c.maxPackets = count
	}
}

// WithSaveOnFailure automatically writes the .pcap file to dir when the test fails.
func WithSaveOnFailure(dir string) CaptureOption {
	return func(c *captureConfig) {
		c.saveDir = dir
		c.saveOnFailure = true
	}
}

// WithSaveAlways automatically writes the .pcap file to dir when the test finishes.
func WithSaveAlways(dir string) CaptureOption {
	return func(c *captureConfig) {
		c.saveDir = dir
		c.saveAlways = true
	}
}

// PacketCapture represents an active or completed pure-Go gopacket/pcapgo capture on a Node.
type PacketCapture struct {
	node          *Node
	id            uint64
	iface         string
	bpfFilter     string
	packetFilter  func(gopacket.Packet) bool
	containerPath string
	pidFile       string
	logFile       string

	mu      sync.Mutex
	stopped bool
}

// StartCapture injects the pure-Go pcapgo agent into the Node, opens an AF_PACKET socket
// on the target interface, and waits until the socket is actively listening before returning.
func (n *Node) StartCapture(ctx context.Context, opts ...CaptureOption) (*PacketCapture, error) {
	if n.t != nil {
		n.t.Helper()
	}

	hostAgentBin, err := buildPcapAgent()
	if err != nil {
		return nil, err
	}

	if err := n.Container.CopyFileToContainer(ctx, hostAgentBin, containerAgentPath, 0o755); err != nil {
		return nil, fmt.Errorf("copy pcap-agent to %s: %w", n.Name, err)
	}

	cfg := &captureConfig{
		iface:   "any",
		snapLen: 65535,
	}
	for _, opt := range opts {
		opt(cfg)
	}

	id := atomic.AddUint64(&captureCounter, 1)
	base := fmt.Sprintf("/tmp/capture-%d", id)
	pcapPath := base + ".pcap"
	pidPath := base + ".pid"
	readyPath := base + ".ready"
	logPath := base + ".log"

	args := []string{
		containerAgentPath,
		"-iface", cfg.iface,
		"-out", pcapPath,
		"-ready", readyPath,
		"-snaplen", fmt.Sprintf("%d", cfg.snapLen),
	}
	if cfg.maxPackets > 0 {
		args = append(args, "-c", fmt.Sprintf("%d", cfg.maxPackets))
	}
	if cfg.bpfFilter != "" {
		args = append(args, "-filter", fmt.Sprintf("'%s'", cfg.bpfFilter))
	}

	cmdStr := strings.Join(args, " ")
	startScript := fmt.Sprintf(
		"%s > %s 2>&1 & echo $! > %s; "+
			"for i in $(seq 1 50); do "+
			"  if [ -f %s ]; then exit 0; fi; "+
			"  if ! kill -0 $(cat %s) 2>/dev/null; then cat %s >&2; exit 1; fi; "+
			"  sleep 0.02; "+
			"done; "+
			"cat %s >&2; exit 1",
		cmdStr, logPath, pidPath, readyPath, pidPath, logPath, logPath,
	)

	if out, err := n.Exec(ctx, []string{"sh", "-c", startScript}); err != nil {
		return nil, fmt.Errorf("start pcap-agent (%s) on %s: %w (output: %s)", cmdStr, n.Name, err, out)
	}

	cap := &PacketCapture{
		node:          n,
		id:            id,
		iface:         cfg.iface,
		bpfFilter:     cfg.bpfFilter,
		packetFilter:  cfg.packetFilter,
		containerPath: pcapPath,
		pidFile:       pidPath,
		logFile:       logPath,
	}

	if n.t != nil {
		// Because t.Cleanup runs LIFO, this cleanup runs BEFORE CreateNode's container termination.
		n.t.Cleanup(func() {
			cleanupCtx := context.Background()
			_ = cap.Stop(cleanupCtx)

			if cfg.saveAlways || (cfg.saveOnFailure && n.t.Failed()) {
				fileName := fmt.Sprintf("%s-%s-%s-%d.pcap",
					sanitizeName(n.t.Name()), sanitizeName(n.Name), sanitizeName(cfg.iface), id)
				destPath := filepath.Join(cfg.saveDir, fileName)
				if err := cap.SaveToFile(cleanupCtx, destPath); err != nil {
					n.t.Logf("warning: failed to save pcap for %s: %v", n.Name, err)
				} else {
					n.t.Logf("saved packet capture to %s", destPath)
				}
			}
		})
	}

	return cap, nil
}

// Stop gracefully stops the pure-Go capture agent inside the Node and waits for it to flush.
func (c *PacketCapture) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopped {
		return nil
	}

	stopScript := fmt.Sprintf(
		"if [ -f %s ]; then "+
			"  pid=$(cat %s); "+
			"  kill -INT $pid 2>/dev/null || true; "+
			"  for i in $(seq 1 30); do "+
			"    kill -0 $pid 2>/dev/null || break; "+
			"    sleep 0.02; "+
			"  done; "+
			"fi",
		c.pidFile, c.pidFile,
	)
	if _, err := c.node.Exec(ctx, []string{"sh", "-c", stopScript}); err != nil {
		return fmt.Errorf("stop pcap-agent on %s: %w", c.node.Name, err)
	}

	c.stopped = true
	return nil
}

// Packets reads the captured .pcap bytes from the container and decodes them natively
// in Go using pcapgo.NewReader and gopacket.NewPacket.
func (c *PacketCapture) Packets(ctx context.Context) ([]gopacket.Packet, error) {
	raw, err := c.Bytes(ctx)
	if err != nil {
		return nil, err
	}

	reader, err := pcapgo.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("open pcapgo reader on %s: %w", c.node.Name, err)
	}

	linkType := reader.LinkType()
	var packets []gopacket.Packet
	for {
		data, ci, err := reader.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("read packet from pcapgo reader on %s: %w", c.node.Name, err)
		}

		// For LinkTypeRaw, determine IPv4 vs IPv6 from the first nibble
		decoder := gopacket.Decoder(linkType)
		if linkType == layers.LinkTypeRaw && len(data) > 0 {
			switch data[0] >> 4 {
			case 4:
				decoder = layers.LayerTypeIPv4
			case 6:
				decoder = layers.LayerTypeIPv6
			}
		}

		pkt := gopacket.NewPacket(data, decoder, gopacket.Default)
		pkt.Metadata().CaptureInfo = ci

		if c.packetFilter != nil && !c.packetFilter(pkt) {
			continue
		}
		packets = append(packets, pkt)
	}

	return packets, nil
}

// DumpText formats all captured packets into human-readable summary lines using gopacket.
func (c *PacketCapture) DumpText(ctx context.Context) (string, error) {
	pkts, err := c.Packets(ctx)
	if err != nil {
		return "", err
	}
	lines := make([]string, 0, len(pkts))
	for _, pkt := range pkts {
		lines = append(lines, FormatPacketSummary(pkt))
	}
	return strings.Join(lines, "\n"), nil
}

// FormatPacketSummary formats a single gopacket.Packet into a concise one-line summary.
func FormatPacketSummary(pkt gopacket.Packet) string {
	ts := pkt.Metadata().Timestamp.Format("15:04:05.000000")
	var srcIP, dstIP string
	if ip4, ok := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		srcIP, dstIP = ip4.SrcIP.String(), ip4.DstIP.String()
	} else if ip6, ok := pkt.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		srcIP, dstIP = ip6.SrcIP.String(), ip6.DstIP.String()
	}

	if udp, ok := pkt.Layer(layers.LayerTypeUDP).(*layers.UDP); ok {
		return fmt.Sprintf("%s IP %s:%d > %s:%d: UDP, payload=%dB",
			ts, srcIP, uint16(udp.SrcPort), dstIP, uint16(udp.DstPort), len(udp.Payload))
	}
	if tcp, ok := pkt.Layer(layers.LayerTypeTCP).(*layers.TCP); ok {
		return fmt.Sprintf("%s IP %s:%d > %s:%d: TCP, seq=%d, payload=%dB",
			ts, srcIP, uint16(tcp.SrcPort), dstIP, uint16(tcp.DstPort), tcp.Seq, len(tcp.Payload))
	}
	if icmp4, ok := pkt.Layer(layers.LayerTypeICMPv4).(*layers.ICMPv4); ok {
		return fmt.Sprintf("%s IP %s > %s: ICMPv4 %s, id=%d, seq=%d",
			ts, srcIP, dstIP, icmp4.TypeCode.String(), icmp4.Id, icmp4.Seq)
	}
	return fmt.Sprintf("%s %s -> %s (%d bytes)", ts, srcIP, dstIP, len(pkt.Data()))
}

// Bytes copies the raw .pcap binary content out of the container.
func (c *PacketCapture) Bytes(ctx context.Context) ([]byte, error) {
	rc, err := c.node.Container.CopyFileFromContainer(ctx, c.containerPath)
	if err != nil {
		return nil, fmt.Errorf("copy pcap %s from %s: %w", c.containerPath, c.node.Name, err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("read pcap stream from %s: %w", c.node.Name, err)
	}
	return data, nil
}

// SaveToFile stops the capture (if still running) and writes the .pcap file to hostPath.
func (c *PacketCapture) SaveToFile(ctx context.Context, hostPath string) error {
	_ = c.Stop(ctx)

	data, err := c.Bytes(ctx)
	if err != nil {
		return err
	}

	if dir := filepath.Dir(hostPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create pcap output dir %s: %w", dir, err)
		}
	}

	if err := os.WriteFile(hostPath, data, 0o644); err != nil {
		return fmt.Errorf("write pcap file %s: %w", hostPath, err)
	}
	return nil
}

func sanitizeName(s string) string {
	r := strings.NewReplacer("/", "-", " ", "-", "_", "-", ":", "-")
	return strings.ToLower(r.Replace(s))
}
