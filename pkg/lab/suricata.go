package lab

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// SuricataOption configures a Suricata instance started on a Node.
type SuricataOption func(*suricataConfig)

type suricataConfig struct {
	interfaces []string
	rules      []string
	configPath string
}

// WithSuricataInterfaces specifies the network interfaces for Suricata to inspect (e.g. "eth0", "eth1").
// Defaults to ["eth0"] if not specified.
func WithSuricataInterfaces(ifaces ...string) SuricataOption {
	return func(c *suricataConfig) {
		c.interfaces = append(c.interfaces, ifaces...)
	}
}

// WithSuricataRule adds a Suricata signature rule to local.rules.
// May be called multiple times to add multiple rules.
func WithSuricataRule(rule string) SuricataOption {
	return func(c *suricataConfig) {
		c.rules = append(c.rules, rule)
	}
}

// WithSuricataRules adds multiple Suricata signature rules to local.rules.
func WithSuricataRules(rules ...string) SuricataOption {
	return func(c *suricataConfig) {
		c.rules = append(c.rules, rules...)
	}
}

// WithSuricataConfig overrides the path to suricata.yaml inside the Node (defaults to "/etc/suricata/suricata.yaml").
func WithSuricataConfig(configPath string) SuricataOption {
	return func(c *suricataConfig) {
		c.configPath = configPath
	}
}

// SuricataAlertMetadata holds the alert-specific fields from a Suricata EVE JSON event.
type SuricataAlertMetadata struct {
	Action      string `json:"action"`
	GID         int    `json:"gid"`
	SignatureID uint64 `json:"signature_id"`
	Rev         int    `json:"rev"`
	Signature   string `json:"signature"`
	Category    string `json:"category"`
	Severity    int    `json:"severity"`
}

// SuricataEVEEvent represents a decoded JSON event from /var/log/suricata/eve.json.
type SuricataEVEEvent struct {
	Timestamp string                 `json:"timestamp"`
	FlowID    uint64                 `json:"flow_id"`
	InIface   string                 `json:"in_iface"`
	EventType string                 `json:"event_type"`
	SrcIP     string                 `json:"src_ip"`
	SrcPort   uint16                 `json:"src_port"`
	DestIP    string                 `json:"dest_ip"`
	DestPort  uint16                 `json:"dest_port"`
	Proto     string                 `json:"proto"`
	Alert     *SuricataAlertMetadata `json:"alert,omitempty"`
}

// Suricata represents a running or stopped Suricata IDS/IPS instance inside a Node.
type Suricata struct {
	node      *Node
	logDir    string
	pidFile   string
	rulesFile string

	mu      sync.Mutex
	stopped bool
}

// InstallSuricata installs the suricata package inside an Alpine-based Node if it is not already present.
// It uses --no-scripts to skip downloading external rule sets during apk post-install.
func (n *Node) InstallSuricata(ctx context.Context) error {
	if n.t != nil {
		n.t.Helper()
	}

	installCmd := "command -v suricata >/dev/null 2>&1 || apk add --no-cache --no-scripts suricata"
	if out, err := n.Exec(ctx, []string{"sh", "-c", installCmd}); err != nil {
		return fmt.Errorf("install suricata on %s: %w (output: %s)", n.Name, err, out)
	}
	return nil
}

// StartSuricata ensures Suricata is installed on the Node, writes any configured rules,
// starts Suricata in daemon mode, and waits until the packet processing engine is ready.
func (n *Node) StartSuricata(ctx context.Context, opts ...SuricataOption) (*Suricata, error) {
	if n.t != nil {
		n.t.Helper()
	}

	if err := n.InstallSuricata(ctx); err != nil {
		return nil, err
	}

	cfg := &suricataConfig{
		configPath: "/etc/suricata/suricata.yaml",
	}
	for _, opt := range opts {
		opt(cfg)
	}
	if len(cfg.interfaces) == 0 {
		cfg.interfaces = []string{"eth0"}
	}

	logDir := "/var/log/suricata"
	pidFile := "/var/run/suricata.pid"
	rulesFile := "/etc/suricata/rules/local.rules"
	logFile := logDir + "/suricata.log"

	rulesContent := strings.Join(cfg.rules, "\n")
	if rulesContent != "" {
		rulesContent += "\n"
	}

	var args []string
	args = append(args,
		"suricata",
		"-c", cfg.configPath,
		"-k", "none",
		"-l", logDir,
		"-D",
		"--pidfile", pidFile,
	)
	if len(cfg.rules) > 0 {
		args = append(args, "-S", rulesFile)
	}
	for _, iface := range cfg.interfaces {
		args = append(args, "-i", iface)
	}

	cmdStr := strings.Join(args, " ")
	startScript := fmt.Sprintf(
		"mkdir -p %s /etc/suricata/rules /var/run/suricata && "+
			"rm -f %s %s/fast.log %s/eve.json %s && "+
			"cat <<'EOF' > %s\n%sEOF\n"+
			"%s && "+
			"for i in $(seq 1 100); do "+
			"  if grep -qi 'engine started' %s 2>/dev/null; then exit 0; fi; "+
			"  if [ -f %s ] && ! kill -0 $(cat %s) 2>/dev/null; then cat %s >&2; exit 1; fi; "+
			"  sleep 0.05; "+
			"done; "+
			"cat %s >&2; exit 1",
		logDir,
		pidFile, logDir, logDir, logFile,
		rulesFile, rulesContent,
		cmdStr,
		logFile,
		pidFile, pidFile, logFile,
		logFile,
	)

	if out, err := n.Exec(ctx, []string{"sh", "-c", startScript}); err != nil {
		return nil, fmt.Errorf("start suricata (%s) on %s: %w (output: %s)", cmdStr, n.Name, err, out)
	}

	s := &Suricata{
		node:      n,
		logDir:    logDir,
		pidFile:   pidFile,
		rulesFile: rulesFile,
	}

	if n.t != nil {
		n.t.Cleanup(func() {
			_ = s.Stop(context.Background())
		})
	}

	return s, nil
}

// Stop gracefully stops the Suricata daemon inside the Node and waits for it to flush logs.
func (s *Suricata) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.stopped {
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
		s.pidFile, s.pidFile,
	)
	if _, err := s.node.Exec(ctx, []string{"sh", "-c", stopScript}); err != nil {
		return fmt.Errorf("stop suricata on %s: %w", s.node.Name, err)
	}

	s.stopped = true
	return nil
}

// FastLog stops Suricata (if still running) to flush buffered output and returns the contents of fast.log.
func (s *Suricata) FastLog(ctx context.Context) (string, error) {
	if err := s.Stop(ctx); err != nil {
		return "", err
	}
	fastLogPath := s.logDir + "/fast.log"
	out, err := s.node.Exec(ctx, []string{"sh", "-c", fmt.Sprintf("cat %s 2>/dev/null || true", fastLogPath)})
	if err != nil {
		return "", fmt.Errorf("read %s on %s: %w", fastLogPath, s.node.Name, err)
	}
	return out, nil
}

// EVEEvents stops Suricata (if still running) to flush buffered output and parses all JSON lines from eve.json.
func (s *Suricata) EVEEvents(ctx context.Context) ([]SuricataEVEEvent, error) {
	if err := s.Stop(ctx); err != nil {
		return nil, err
	}
	evePath := s.logDir + "/eve.json"
	raw, err := s.node.Exec(ctx, []string{"sh", "-c", fmt.Sprintf("cat %s 2>/dev/null || true", evePath)})
	if err != nil {
		return nil, fmt.Errorf("read %s on %s: %w", evePath, s.node.Name, err)
	}

	var events []SuricataEVEEvent
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var ev SuricataEVEEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			return nil, fmt.Errorf("unmarshal eve.json line on %s: %w (%s)", s.node.Name, err, line)
		}
		events = append(events, ev)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan eve.json on %s: %w", s.node.Name, err)
	}
	return events, nil
}

// Alerts stops Suricata (if still running) and returns all "alert" events from eve.json.
func (s *Suricata) Alerts(ctx context.Context) ([]SuricataEVEEvent, error) {
	events, err := s.EVEEvents(ctx)
	if err != nil {
		return nil, err
	}
	var alerts []SuricataEVEEvent
	for _, ev := range events {
		if ev.EventType == "alert" && ev.Alert != nil {
			alerts = append(alerts, ev)
		}
	}
	return alerts, nil
}
