// This program demonstrates attaching an eBPF program to a network interface
// with TC to manipulate the egress traffic. In this particular case we make logic
// on the source ip to choose a different egress interface / next hop.
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS redirect redirect.c -- -I../headers

func main() {
	objs := &redirectObjects{}
	if err := loadRedirectObjects(objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Attach the filter to the eth0 interface, all the egress traffic going
	// through eth0 is forwarded to our program.
	attachFilter("eth0", objs.redirectPrograms.Redirect)

	// We apply the logic only if the source IP is 192.168.1.5
	srcIP := net.ParseIP("192.168.1.5")

	// We redirect the traffic via eth1 using as nexthop, by filling the map.
	nextHopIP := net.ParseIP("10.111.221.21")
	viaInterface := "eth1"
	enableRedirect(srcIP, nextHopIP, viaInterface, objs.RedirectMapIpv4)
}

func attachFilter(attachTo string, program *ebpf.Program) error {
	devID, err := net.InterfaceByName(attachTo)
	if err != nil {
		return fmt.Errorf("could not get interface ID: %w", err)
	}

	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: devID.Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}

	err = netlink.QdiscReplace(qdisc)
	if err != nil {
		return fmt.Errorf("could not get replace qdisc: %w", err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: devID.Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           program.FD(),
		Name:         program.String(),
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return fmt.Errorf("failed to replace tc filter: %w", err)
	}
	return nil
}

func enableRedirect(src, nextHop net.IP, interfaceName string, ebpfMap *ebpf.Map) error {
	eth1ID, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("could not get interface ID: %w", err)
	}

	key, err := ipv4ToInt(src)
	if err != nil {
		return fmt.Errorf("convert ip failed %w", err)
	}

	next, err := ipv4ToInt(nextHop)
	if err != nil {
		return fmt.Errorf("convert ip failed %w", err)
	}
	record := struct {
		interfaceID uint32
		nextHopIP   uint32
	}{
		uint32(eth1ID.Index),
		next,
	}
	err = ebpfMap.Put(key, record)
	if err != nil {
		return fmt.Errorf("add to map failed %w", err)
	}
	return nil
}

func ipv4ToInt(ipaddr net.IP) (uint32, error) {
	if ipaddr.To4() == nil {
		return 0, fmt.Errorf("the address %s is not an ipv4 address", ipaddr)
	}
	return binary.BigEndian.Uint32(ipaddr.To4()), nil
}
