//go:build linux

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
)

func main() {
	iface := flag.String("iface", "wg0", "WireGuard TUN interface name")
	mtu := flag.Int("mtu", device.DefaultMTU, "TUN interface MTU")
	uapiFile := flag.String("uapi", "", "path to initial UAPI configuration file")
	readyFile := flag.String("ready", "", "file created once TUN and UAPI are up")
	statusMode := flag.Bool("status", false, "query UAPI status of running wireguard-go interface")
	flag.Parse()

	if *statusMode {
		if err := queryStatus(*iface); err != nil {
			fmt.Fprintf(os.Stderr, "status error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if err := ensureTunDeviceNode(); err != nil {
		fmt.Fprintf(os.Stderr, "ensure /dev/net/tun: %v\n", err)
		os.Exit(1)
	}

	tdev, err := tun.CreateTUN(*iface, *mtu)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create TUN %s: %v\n", *iface, err)
		os.Exit(1)
	}

	logger := device.NewLogger(device.LogLevelError, fmt.Sprintf("(%s) ", *iface))
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	defer dev.Close()

	if *uapiFile != "" {
		confBytes, err := os.ReadFile(*uapiFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read uapi config %s: %v\n", *uapiFile, err)
			os.Exit(1)
		}
		if err := dev.IpcSet(string(confBytes)); err != nil {
			fmt.Fprintf(os.Stderr, "apply uapi config: %v\n", err)
			os.Exit(1)
		}
	}

	if err := dev.Up(); err != nil {
		fmt.Fprintf(os.Stderr, "bring device up: %v\n", err)
		os.Exit(1)
	}

	fileUAPI, err := ipc.UAPIOpen(*iface)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open UAPI socket: %v\n", err)
		os.Exit(1)
	}

	uapiListener, err := ipc.UAPIListen(*iface, fileUAPI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen UAPI socket: %v\n", err)
		os.Exit(1)
	}
	defer uapiListener.Close()

	go func() {
		for {
			c, err := uapiListener.Accept()
			if err != nil {
				return
			}
			go dev.IpcHandle(c)
		}
	}()

	if *readyFile != "" {
		if err := os.WriteFile(*readyFile, []byte("ready\n"), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write ready file: %v\n", err)
			os.Exit(1)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case <-sigCh:
	case <-dev.Wait():
	}
}

func ensureTunDeviceNode() error {
	if _, err := os.Stat("/dev/net/tun"); err == nil {
		return nil
	}
	if err := os.MkdirAll("/dev/net", 0o755); err != nil {
		return err
	}
	dev := int(unix.Mkdev(10, 200))
	if err := unix.Mknod("/dev/net/tun", unix.S_IFCHR|0o666, dev); err != nil && err != unix.EEXIST {
		return err
	}
	return nil
}

func queryStatus(iface string) error {
	sockPath := fmt.Sprintf("/var/run/wireguard/%s.sock", iface)
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		return fmt.Errorf("dial %s: %w", sockPath, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))

	if _, err := io.WriteString(c, "get=1\n\n"); err != nil {
		return err
	}
	if uc, ok := c.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}

	var buf bytes.Buffer
	tmp := make([]byte, 4096)
	for {
		n, readErr := c.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
			if bytes.HasSuffix(buf.Bytes(), []byte("\n\n")) {
				break
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				break
			}
			return readErr
		}
	}
	fmt.Print(buf.String())
	return nil
}
