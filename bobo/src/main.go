package main

import (
    "fmt"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
)

const (
    IP  = 0
    TCP = 1
    UDP = 2
)

type Node struct {
    addr    string
    port    string //uint16
}

type Flow struct {
    node1   Node
    node2   Node
    proto   uint8
}

func printFlow(flow Flow) {
    var output string

    switch flow.proto {
    case IP:
        output = "IP  " + flow.node1.addr + " --> " +  flow.node2.addr
    case TCP:
        output = "TCP " + flow.node1.addr + ":" + flow.node1.port + " --> " + flow.node2.addr + ":" + flow.node2.port
    case UDP:
        output = "UDP " + flow.node1.addr + ":" + flow.node1.port + " --> " + flow.node2.addr + ":" + flow.node2.port
    }

    fmt.Println (output)
}

func main() {

    connections := make(map[Node]Node)

    handler, err := pcap.OpenLive("wlp2s0", 200, true, pcap.BlockForever)
    if err != nil {
        panic(err)
    }

    err = handler.SetBPFFilter("ip")
    if err != nil {
        panic(err)
    }

    packetSource := gopacket.NewPacketSource(handler, handler.LinkType())

    for packet := range packetSource.Packets() {

        flow := Flow{}

        net := packet.NetworkLayer()
        if net != nil {
            flow.node1.addr = net.NetworkFlow().Src().String()
            flow.node2.addr = net.NetworkFlow().Dst().String()
            flow.proto = IP
        }

        tcplayer := packet.Layer(layers.LayerTypeTCP)
        if tcplayer != nil {
            tcp, _  := tcplayer.(*layers.TCP)
            flow.node1.port = tcp.TransportFlow().Src().String()
            flow.node2.port = tcp.TransportFlow().Dst().String()
            flow.proto      = TCP
        }

        udplayer := packet.Layer(layers.LayerTypeUDP)
        if udplayer != nil {
            udp, _  := udplayer.(*layers.UDP)
            flow.node1.port = udp.TransportFlow().Src().String()
            flow.node2.port = udp.TransportFlow().Dst().String()
            flow.proto      = UDP
        }

        _, ok1 := connections[flow.node1]
        _, ok2 := connections[flow.node2]

       if ok1 || ok2 {
            continue
       }

        connections[flow.node1] = flow.node2
        printFlow(flow)
        //fmt.Println (connections)

    }
}
