// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and writes the packet count by IP to an LRU hash map.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second.
// It is possible to modify the XDP program to drop or redirect packets
// as well -- give it a try!
// This example depends on bpf_link, available in Linux kernel version 5.7 or newer.
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// erase content of the map after this iterations
const eraseEvery = 5

// mapping between integer value and L4 protocol string
var (
	currIter = 0
	protoMap = map[uint8]string{
		1:  "ICMP",
		6:  "TCP",
		17: "UDP",
	}
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp_tcx.c -- -I../headers

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("Please specify a network interface")
	}

	// Look up the network interface by name.
	ifaceName := os.Args[1]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("lookup network iface %q: %s", ifaceName, err)
	}

	// Load pre-compiled programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	// Attach the program to Ingress XDP.
	l, err := link.AttachXDP(link.XDPOptions{
		Interface: iface.Index,
		Program:   objs.IngressProgFunc,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to INGRESS iface %q (index %d)", iface.Name, iface.Index)

	// Attach the program to Egress TC.
	l2, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.EgressProgFunc,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer l2.Close()

	log.Printf("Attached TCx program to EGRESS iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Print the contents of the BPF hash map.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		handleMapContents(objs.StatsMap)
	}
}

// handleMapContents prints the content of the map into a string.
// For each entry (if any), a row is formatted with the following content:
// <src_addr>:<src_port> <dst_addr>:<dst_port> Proto:<l4_proto> => Ingress:<in_packets> Egress:<eg_packets>
// Every nth calls to this function, the entire content of the Hash map is erased
// (lru map would automatically remove old keys, but can also remove additional keys
// so we use hash map to keep constant behaviour)
func handleMapContents(m *ebpf.Map) {
	var (
		sb   strings.Builder
		key  bpfSessionKey
		val  bpfSessionValue
		keys []bpfSessionKey
	)
	currIter++
	needsErase := currIter%eraseEvery == 0

	if needsErase {
		keys = make([]bpfSessionKey, 0)
	}

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sb.WriteString(fmt.Sprintf("\t%s:%d - %s:%d Proto:%s => Ingress:%d Egress:%d\n",
			intToIp(key.Saddr), portToLE(key.Sport), intToIp(key.Daddr), portToLE(key.Dport),
			protoMap[key.Proto], val.InCount, val.EgCount))
		if needsErase {
			keys = append(keys, key)
		}
	}
	if iter.Err() != nil {
		log.Printf("Error reading map: %s", iter.Err())
		return
	}

	log.Printf("Map contents:\n%s", sb.String())

	if !needsErase {
		return
	}

	n, err := m.BatchDelete(keys, nil)
	if err != nil {
		log.Printf("Error erasing map: %s", err)
		return
	}
	log.Printf("Successfully Erased Map content (%d elements) at Iteration n. %d\n", n, currIter)
}

// intToIp convert an int32 value retrieved from the network
// traffic (big endian) into a netip.Addr
func intToIp(val uint32) netip.Addr {
	a4 := [4]byte{}
	binary.LittleEndian.PutUint32(a4[:], val)
	return netip.AddrFrom4(a4)
}

// portToLE convert a uint16 value retrieved from the network
// traffic (big endian) into a little endian
func portToLE(val uint16) uint16 {
	p2 := [2]byte{}
	binary.LittleEndian.PutUint16(p2[:], val)
	return binary.LittleEndian.Uint16(p2[:])
}
