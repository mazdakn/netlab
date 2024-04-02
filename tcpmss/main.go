package main

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func main() {
	var d net.Dialer
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	d.Control = func(network, address string, c syscall.RawConn) error {
		fmt.Printf("Network: %v, address: %v\n", network, address)
		var operr error
		err := c.Control(func(fd uintptr) {
			fmt.Printf("fd: %v\n", fd)
			operr = syscall.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_MAXSEG, 1001)
		})
		if err != nil {
			fmt.Printf("error in control: %v\n", err)
			return err
		}
		return operr
	}

	conn, err := d.DialContext(ctx, "tcp", ":9999")
	if err != nil {
		fmt.Printf("Failed to accept connections: %v\n", err)
	}
	conn.Write([]byte("Hello\n"))
	fmt.Printf("Sent data from %v to %v\n", conn.LocalAddr().String(), conn.RemoteAddr().String())
	conn.Close()
}
