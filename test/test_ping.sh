#!/usr/bin/env bash

sudo ./netns_network_examples/simple/2hosts_1router.sh -c
sudo ip netns exec r1 ../cmd/lwt_capture/main -dst 2001:db8:20::2/128 -link r1_h2 -lwt_hook xmit &
sudo ip netns exec h1 ping -c 3 2001:db8:20::2
sudo cat /sys/kernel/tracing/trace
sudo ip netns exec r1 ip -6 r
sudo ./netns_network_examples/simple/2hosts_1router.sh -d
