package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"github.com/cilium/ebpf/perf"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	cap "github.com/shu1r0/lwt_in_ebpf_capture/pkg/ebpf"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"net"
	"os"
	"os/signal"
)

type perfEventItem struct {
	Cookie  uint16
	Pkt_len uint16
}

func main() {
	var (
		dst_s = flag.String("dst", "2001:db8:20::2/128", "server ip address")
		link  = flag.String("link", "r1_h2", "link")
		hook  = flag.String("lwt_hook", "xmit", "in, out, xmit")
	)
	flag.Parse()

	bpfDriver, err := cap.NewEBpfObjects(nil)
	if err != nil {
		panic(fmt.Errorf("Failed new driver: %v\n", err))
	}

	bpfEncap := netlink.BpfEncap{}

	switch *hook {
	case "in":
		if err := bpfEncap.SetProg(nl.LWT_BPF_IN, bpfDriver.CaptureIn.FD(), "lwt_in/capture"); err != nil {
			panic(fmt.Errorf("set prog error : %s", err))
		}
	case "xmit":
		if err := bpfEncap.SetProg(nl.LWT_BPF_XMIT, bpfDriver.CaptureXmit.FD(), "lwt_xmit/capture"); err != nil {
			panic(fmt.Errorf("set prog error : %s", err))
		}
	case "out":
		if err := bpfEncap.SetProg(nl.LWT_BPF_OUT, bpfDriver.CaptureOut.FD(), "lwt_out/capture"); err != nil {
			panic(fmt.Errorf("set prog error : %s", err))
		}

	}

	_, dst, err := net.ParseCIDR(*dst_s)
	if err != nil {
		panic(fmt.Errorf("parse cidr error : %s", err))
	}
	oif, err := netlink.LinkByName(*link)
	if err != nil {
		panic(fmt.Errorf("link by name error : %s", err))
	}
	//gw := net.ParseIP("2001:db8:20::2")
	route := netlink.Route{LinkIndex: oif.Attrs().Index, Dst: dst, Encap: &bpfEncap}
	fmt.Println(route)
	if err := netlink.RouteAdd(&route); err != nil {
		panic(fmt.Errorf("route add error : %s", err))
	}

	perfEvent, err := perf.NewReader(bpfDriver.PerfMap, 4096)
	if err != nil {
		panic(fmt.Errorf("perf read error : %s", err))
	}

	ctrlC := make(chan os.Signal, 1)
	signal.Notify(ctrlC, os.Interrupt)

	fmt.Println("Wait perf event...")

	go func() {
		var event perfEventItem
		for {
			evnt, err := perfEvent.Read()
			if err != nil {
				if errors.Unwrap(err) == perf.ErrClosed {
					break
				}
				panic(fmt.Errorf("perf event read error : %s", err))
			}
			reader := bytes.NewReader(evnt.RawSample)
			if err := binary.Read(reader, binary.LittleEndian, &event); err != nil {
				panic(fmt.Errorf("binary read error : %s", err))
			}
			if len(evnt.RawSample)-4 > 0 {
				//fmt.Println(hex.EncodeToString(evnt.RawSample))
				pkt := gopacket.NewPacket(evnt.RawSample[4:], layers.LayerTypeIPv6, gopacket.Default)
				fmt.Println(pkt.Dump())
			} else {
				fmt.Println("Invalid event length")
			}
		}
	}()
	<-ctrlC
	fmt.Println("End.")
	if err := perfEvent.Close(); err != nil {
		panic(fmt.Errorf("close error : %s", err))
	}
	netlink.RouteDel(&route)
}
