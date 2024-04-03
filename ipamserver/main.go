package main

import (
	"flag"
)

const (
	defaultAddr string = "localhost:8080"
)

func main() {
	// TODO: setup

	// Parse arguments and get the address to listen to.
	addrPtr := flag.String("addr", defaultAddr, "Address to bind to")
	flag.Parse()
	addr := *addrPtr

	// Create the IPAM Server and start it.
	ipamSrv := newIPAMServer(addr)
	ipamSrv.Start()
}
