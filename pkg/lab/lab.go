package lab

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	tcnetwork "github.com/testcontainers/testcontainers-go/network"
)

// Lab manages the lifecycle of networks and container nodes for a single Go test.
type Lab struct {
	t        testing.TB
	networks map[string]*Network
	nodes    map[string]*Node
}

// Network represents an isolated Docker bridge network with a dedicated IPv4 subnet.
type Network struct {
	Name       string
	Subnet     string
	HostBridge string
	DockerNet  *testcontainers.DockerNetwork
}

// NetworkAttachment binds a Node to a Lab Network with an explicit static IPv4 address.
type NetworkAttachment struct {
	Network *Network
	IPv4    string
}

// NodeOption customizes a Node's configuration prior to startup.
type NodeOption func(*nodeConfig)

type nodeConfig struct {
	image       string
	attachments []NetworkAttachment
	sysctls     map[string]string
	capAdd      []string
	cmd         []string
}

// WithImage overrides the container image for a Node instead of building the default lab image.
func WithImage(image string) NodeOption {
	return func(c *nodeConfig) {
		c.image = image
	}
}

// WithNetwork attaches the Node to a Network with a static IPv4 address.
// Call multiple times to create a multi-homed node (such as a router/gateway).
func WithNetwork(net *Network, ipv4 string) NodeOption {
	return func(c *nodeConfig) {
		c.attachments = append(c.attachments, NetworkAttachment{
			Network: net,
			IPv4:    ipv4,
		})
	}
}

// WithSysctl sets a namespace sysctl parameter on the Node.
func WithSysctl(key, value string) NodeOption {
	return func(c *nodeConfig) {
		c.sysctls[key] = value
	}
}

// WithIPForwarding enables IPv4 packet forwarding and disables ICMP redirect sending on the Node.
func WithIPForwarding() NodeOption {
	return func(c *nodeConfig) {
		c.sysctls["net.ipv4.ip_forward"] = "1"
		c.sysctls["net.ipv4.conf.all.send_redirects"] = "0"
		c.sysctls["net.ipv4.conf.default.send_redirects"] = "0"
	}
}

// Node represents a running container participating in a networking scenario.
type Node struct {
	t         testing.TB
	Name      string
	Container testcontainers.Container
	IPs       map[string]string // keyed by Network.Name
}

// New creates a new Lab tied to the lifecycle of t.
func New(t testing.TB) *Lab {
	t.Helper()
	return &Lab{
		t:        t,
		networks: make(map[string]*Network),
		nodes:    make(map[string]*Node),
	}
}

// CreateNetwork creates an isolated bridge network with an explicit IPv4 subnet (e.g. "172.28.10.0/24")
// and host bridge gateway IP (e.g. "172.28.10.1") so containers can use deterministic static IPs.
func (l *Lab) CreateNetwork(ctx context.Context, name, subnet, hostBridgeIP string) (*Network, error) {
	l.t.Helper()

	prefix, err := netip.ParsePrefix(subnet)
	if err != nil {
		return nil, fmt.Errorf("parse subnet %q for network %s: %w", subnet, name, err)
	}
	gwAddr, err := netip.ParseAddr(hostBridgeIP)
	if err != nil {
		return nil, fmt.Errorf("parse gateway IP %q for network %s: %w", hostBridgeIP, name, err)
	}

	dockerNet, err := tcnetwork.New(
		ctx,
		tcnetwork.WithDriver("bridge"),
		tcnetwork.WithIPAM(&network.IPAM{
			Driver: "default",
			Config: []network.IPAMConfig{
				{
					Subnet:  prefix,
					Gateway: gwAddr,
				},
			},
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("create network %s (%s): %w", name, subnet, err)
	}

	testcontainers.CleanupNetwork(l.t, dockerNet)

	net := &Network{
		Name:       name,
		Subnet:     subnet,
		HostBridge: hostBridgeIP,
		DockerNet:  dockerNet,
	}
	l.networks[name] = net
	return net, nil
}

// CreateNode starts a container node with NET_ADMIN capability and attaches it to all requested networks.
func (l *Lab) CreateNode(ctx context.Context, name string, opts ...NodeOption) (*Node, error) {
	l.t.Helper()

	cfg := &nodeConfig{
		sysctls: make(map[string]string),
		capAdd:  []string{"NET_ADMIN", "NET_RAW"},
		// Trap SIGTERM so container teardown completes immediately instead of waiting 10s
		cmd: []string{"sh", "-c", "trap 'exit 0' TERM INT; sleep infinity & wait"},
	}
	for _, opt := range opts {
		opt(cfg)
	}

	ips := make(map[string]string, len(cfg.attachments))
	parsedAddrs := make(map[string]netip.Addr, len(cfg.attachments))
	for _, att := range cfg.attachments {
		addr, err := netip.ParseAddr(att.IPv4)
		if err != nil {
			return nil, fmt.Errorf("invalid IPv4 %q for node %s on network %s: %w", att.IPv4, name, att.Network.Name, err)
		}
		ips[att.Network.Name] = att.IPv4
		parsedAddrs[att.Network.DockerNet.Name] = addr
	}

	req := testcontainers.ContainerRequest{
		Image: cfg.image,
		Cmd:   cfg.cmd,
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.CapAdd = cfg.capAdd
			hc.Sysctls = cfg.sysctls
		},
		EndpointSettingsModifier: func(settings map[string]*network.EndpointSettings) {
			for _, att := range cfg.attachments {
				netName := att.Network.DockerNet.Name
				settings[netName] = &network.EndpointSettings{
					NetworkID: att.Network.DockerNet.ID,
					Aliases:   []string{name},
					IPAMConfig: &network.EndpointIPAMConfig{
						IPv4Address: parsedAddrs[netName],
					},
				}
			}
		},
	}

	if cfg.image == "" {
		_, thisFile, _, _ := runtime.Caller(0)
		req.FromDockerfile = testcontainers.FromDockerfile{
			Context:    filepath.Dir(thisFile),
			Dockerfile: "Dockerfile.node",
			Repo:       "netlab/node",
			Tag:        "latest",
			KeepImage:  true,
		}
	}

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	testcontainers.CleanupContainer(l.t, ctr)
	if err != nil {
		return nil, fmt.Errorf("start node %s: %w", name, err)
	}

	node := &Node{
		t:         l.t,
		Name:      name,
		Container: ctr,
		IPs:       ips,
	}
	l.nodes[name] = node
	return node, nil
}

// Exec runs a command inside the Node and returns its combined stdout/stderr output.
// It returns a non-nil error if the command exits with a non-zero status code.
func (n *Node) Exec(ctx context.Context, cmd []string) (string, error) {
	code, reader, err := n.Container.Exec(ctx, cmd, tcexec.Multiplexed())
	if err != nil {
		return "", fmt.Errorf("exec %v on %s: %w", cmd, n.Name, err)
	}

	var out string
	if reader != nil {
		b, readErr := io.ReadAll(reader)
		if readErr != nil {
			return "", fmt.Errorf("read exec output for %v on %s: %w", cmd, n.Name, readErr)
		}
		out = strings.TrimSpace(string(b))
	}

	if code != 0 {
		return out, fmt.Errorf("command %v on %s exited with %d: %s", cmd, n.Name, code, out)
	}
	return out, nil
}

// AddRoute adds an IPv4 static route inside the Node via the specified next-hop gateway IP.
func (n *Node) AddRoute(ctx context.Context, dstCIDR, viaGatewayIP string) error {
	_, err := n.Exec(ctx, []string{"ip", "route", "replace", dstCIDR, "via", viaGatewayIP})
	if err != nil {
		return fmt.Errorf("add route %s via %s on %s: %w", dstCIDR, viaGatewayIP, n.Name, err)
	}
	return nil
}

// Ping sends ICMP echo requests from the Node to targetIP and fails if any packets are lost.
func (n *Node) Ping(ctx context.Context, targetIP string, count int) (string, error) {
	return n.Exec(ctx, []string{
		"ping", "-c", fmt.Sprintf("%d", count), "-W", "3", targetIP,
	})
}
