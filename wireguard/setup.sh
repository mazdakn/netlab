#!/bin/bash

function setup() {
    local id="$1"
    local addr0="10.10.1$id.10/24"
    local addr1="10.10.1$id.11/24"
    local name="$2"
    local iface0="$name-0"
    local iface1="$name-1"
    
    echo "Creating $name with $iface0($addr0) $iface1($addr1) interfaces"
    ip netns add $name
    ip link add $iface0 type veth peer name $iface1
    
    ip link set dev $iface0 up
    ip addr add $addr0 dev $iface0
    
    ip link set dev $iface1 netns $name
    ip netns exec $name ip link set dev lo up
    ip netns exec $name ip link set dev $iface1 up
    ip netns exec $name ip addr add $addr1 dev $iface1
    ip netns exec $name ip route add default dev $iface1
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
else
    setup 0 "cont0"
    setup 1 "cont1"
    setup 2 "cont2"
fi
