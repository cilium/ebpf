//go:build linux
// +build linux

// This program demonstrates attaching XDP eBPF program to network interface.
// It drops packets who's IP match the given CIDR. BPF_MAP_TYPE_LPM_TRIE is used to perform IP prefix matching.
// Only IPv4 is supported for this example.
// The number of packets dropped is printed when program exits.

package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type LPMMapKey struct {
	PrefixLength uint32
	IPv4Address  [4]byte
}

var (
	cidr          = flag.String("cidr", "", "cidr to block, e.g. 192.168.1.0/24")
	interfaceName = flag.String("interface", "", "network interface to attach program to, e.g. eth0")
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf xdp_firewall.c -- -I../headers
func main() {
	flag.Parse()

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatal(err)
	}
	defer objs.Close()

	setBlockedCIDR(objs.XdpMap, *cidr)

	// get interface and attch XDP to it
	ifce, err := net.InterfaceByName(*interfaceName)
	if err != nil {
		log.Fatal(err)
	}
	attach, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDropPacket,
		Interface: ifce.Index,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer attach.Close()

	log.Println("firewall started")
	defer printStat(objs.XdpMap)
	waitSignal()
}

func setBlockedCIDR(m *ebpf.Map, cidr string) {
	_, parsedCIDR, err := net.ParseCIDR(cidr)
	if err != nil {
		log.Fatal(err)
	}

	var key LPMMapKey
	prefix, _ := parsedCIDR.Mask.Size()
	key.PrefixLength = uint32(prefix)
	v4Addr := parsedCIDR.IP.To4()
	key.IPv4Address[0] = v4Addr[0]
	key.IPv4Address[1] = v4Addr[1]
	key.IPv4Address[2] = v4Addr[2]
	key.IPv4Address[3] = v4Addr[3]
	err = m.Update(&key, uint64(0), ebpf.UpdateAny)
	if err != nil {
		log.Fatal(err)
	}
}

func printStat(m *ebpf.Map) {
	var (
		key   LPMMapKey
		value uint64
	)
	iterator := m.Iterate()
	log.Println("packets dropped:")
	for iterator.Next(&key, &value) {
		ip := net.IPv4(key.IPv4Address[0], key.IPv4Address[1], key.IPv4Address[2], key.IPv4Address[3])
		log.Printf("%s/%d: %d\n", ip.String(), key.PrefixLength, value)
	}
}

func waitSignal() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)
	sig := <-stopper
	log.Printf("got signal [%s] to exit\n", sig.String())
}
