package main

import (
    "fmt"
    "flag"
    "os"
    "net"
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
    iface   string
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


func parseIfaces() (map[string]string, error) {

    ifaces := make(map[string]string)

    interfaces, err := net.Interfaces()
    if err != nil {
        fmt.Println(err)
        return nil, err
    }

    for _, iface := range interfaces {

        if iface.Flags & net.FlagUp == 0 {
            continue
        }

        if iface.Flags & net.FlagLoopback != 0 {
            continue
        }

        addrs, err := iface.Addrs()
        if err != nil {
            fmt.Println(err)
            continue
        }

        if addrs == nil {
            continue
        }

        for index, addr := range addrs {
            if net.ParseIP(addr.String()).To4 != nil {
                ifaces[addrs[index].String()] = iface.Name
                continue
            }
        }
    }

    return ifaces, nil
}

func printInterfaces(interfaces map[string]string) {

    for addr, iface := range interfaces {
        fmt.Println(iface,":",addr)
    }
}

func processFlow(flows map[string])


func main() {

    pcapFile := flag.String("f", "", "PCAP file to process")
    flag.Parse()

    if *pcapFile == "" {
        fmt.Println("No PCAP file")
        os.Exit(1)
    }

    connections := make(map[Node]Node)
    ingress, egress := make([]Flow)


    /*handler, err := pcap.OpenOffline("wlp2s0", 200, true, pcap.BlockForever)
    if err != nil {
        panic(err)
    }*/

    if _, err := os.Stat(*pcapFile); os.IsNotExist(err) {
        fmt.Println(*pcapFile, "does not exist")
        os.Exit(1)
    }

    ifaces, err := parseIfaces()
    if err != nil {
        fmt.Println(err)
    }

    handler, err := pcap.OpenOffline(*pcapFile)
    if err != nil {
        fmt.Println (err)
    }

    if err := handler.SetBPFFilter("ip"); err != nil {
        fmt.Println(err)
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
            if !tcp.SYN || tcp.ACK {
                continue
            }

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
    }

    processFlows(connections)
}
