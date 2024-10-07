#!/bin/bash

function setup() {
    local id="$1"
    local addr0="10.10.1$id.10/24"
    local addr1="10.10.1$id.11/24"
    local next_hop="10.10.1$id.10"
    local name="$2"
    local iface0="$name-0"
    local iface1="$name-1"

    local wg_iface="wg$id"
    local wg_addr="10.100.100.10$id/24"
    local wg_key="$name.key"
    local wg_pub="$name.pub"
    local wg_conf="$name-wg.conf"
    local log_file="$name.log"
    
    echo "Creating $name with $iface0($addr0) $iface1($addr1) interfaces"
    ip netns add $name
    ip link add $iface0 type veth peer name $iface1
    
    ip link set dev $iface0 up
    ip addr add $addr0 dev $iface0
    
    ip link set dev $iface1 netns $name
    ip netns exec $name ip link set dev lo up
    ip netns exec $name ip link set dev $iface1 up
    ip netns exec $name ip addr add $addr1 dev $iface1
    ip netns exec $name ip route add default via $next_hop dev $iface1

    #ip link add dev $wg_iface type wireguard
    export LOG_LEVEL=verbose
    ip netns exec $name wireguard-go $wg_iface > $log_file 2>&1
    #ip link set dev $wg_iface netns $name
    ip netns exec $name ip addr add $wg_addr dev $wg_iface
    ip netns exec $name wg setconf $wg_iface $wg_conf
    ip netns exec $name ip link set dev $wg_iface up
}

function cleanup() {
    local name="$1"
    echo "Cleaning up netns $name"
    ip netns del $name
}

if [ "$1" == "cleanup" ]; then
    cleanup "cont0"
    cleanup "cont1"
    cleanup "cont2"
    echo "Terminating all wireguard processes"
    pkill wireguard-go
else
    setup 0 "cont0"
    setup 1 "cont1"
    setup 2 "cont2"
fi
