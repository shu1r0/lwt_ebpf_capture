# LWT/eBPF packet capture sample

This is a sample program for using eBPF with LWT hook. This program captures packets matching the ebpf route.

## usage

```bash
$ go run ./cmd/lwt_capture/main.go -h
Usage of /tmp/go-build1182844911/b001/exe/main:
  -dst string
        server ip address (default "2001:db8:20::2/128")
  -link string
        link (default "r1_h2")
  -lwt_hook string
        in, out, xmit (default "xmit")
```

## Capture result
```bash
$ sudo ip netns exec r1 ../cmd/lwt_capture/main -dst 2001:db8:20::2/128 -link r1_h2 -lwt_hook xmit
-- FULL PACKET DATA (104 bytes) ------------------------------------
00000000  60 08 eb 29 00 40 3a 3f  20 01 0d b8 00 10 00 00  |`..).@:? .......|
00000010  00 00 00 00 00 00 00 02  20 01 0d b8 00 20 00 00  |........ .... ..|
00000020  00 00 00 00 00 00 00 02  80 00 f5 e4 62 9c 00 02  |............b...|
00000030  49 f9 87 64 00 00 00 00  30 2b 0b 00 00 00 00 00  |I..d....0+......|
00000040  10 11 12 13 14 15 16 17  18 19 1a 1b 1c 1d 1e 1f  |................|
00000050  20 21 22 23 24 25 26 27  28 29 2a 2b 2c 2d 2e 2f  | !"#$%&'()*+,-./|
00000060  30 31 32 33 34 35 36 37                           |01234567|
--- Layer 1 ---
IPv6	{Contents=[..40..] Payload=[..64..] Version=6 TrafficClass=0 FlowLabel=584489 Length=64 NextHeader=ICMPv6 HopLimit=63 SrcIP=2001:db8:10::2 DstIP=2001:db8:20::2 HopByHop=nil}
00000000  60 08 eb 29 00 40 3a 3f  20 01 0d b8 00 10 00 00  |`..).@:? .......|
00000010  00 00 00 00 00 00 00 02  20 01 0d b8 00 20 00 00  |........ .... ..|
00000020  00 00 00 00 00 00 00 02                           |........|
--- Layer 2 ---
ICMPv6	{Contents=[128, 0, 245, 228] Payload=[..60..] TypeCode=EchoRequest Checksum=62948 TypeBytes=[]}
00000000  80 00 f5 e4                                       |....|
--- Layer 3 ---
ICMPv6Echo	{Contents=[] Payload=[] Identifier=25244 SeqNumber=2}

-- FULL PACKET DATA (104 bytes) ------------------------------------
00000000  60 08 eb 29 00 40 3a 3f  20 01 0d b8 00 10 00 00  |`..).@:? .......|
00000010  00 00 00 00 00 00 00 02  20 01 0d b8 00 20 00 00  |........ .... ..|
00000020  00 00 00 00 00 00 00 02  80 00 a3 85 62 9c 00 03  |............b...|
00000030  4a f9 87 64 00 00 00 00  81 89 0b 00 00 00 00 00  |J..d............|

... 

```


## Run test

Setup git submodule.
```bash
git submodule init
git submodule sync
git submodule update
```

Create netns network.
```bash
sudo ./test/netns_network_examples/simple/2hosts_1router.sh -c
```

Set ebpf program.
```bash
sudo ip netns exec r1 ../cmd/lwt_capture/main -dst 2001:db8:20::2/128 -link r1_h2 -lwt_hook xmit
```

After the ping is executed on another terminal, check the captured data.
```bash
sudo ip netns exec h1 ping -c 3 2001:db8:20::2
```

Clean.
```bash
sudo ./test/netns_network_examples/simple/2hosts_1router.sh -d
```