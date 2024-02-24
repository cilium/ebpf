// This program demonstrates attaching an eBPF program to a network interface
// with Linux TC. The program parses the IPv4 source address
// from packets and writes the Ingress and Egress packet count to an Hash map.
// The userspace program (Go code in this file) prints the content of the map to stdout.
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

// mapping between integer value and L4 protocol string
var protoMap = map[uint8]string{
	1:  "ICMP",
	6:  "TCP",
	17: "UDP",
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf tcx.c -- -I../headers
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

	// Attach the program to Ingress TC.
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.IngressProgFunc,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("could not attach TCx program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached TCx program to INGRESS iface %q (index %d)", iface.Name, iface.Index)

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
		s, err := formatMapContent(objs.StatsMap)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}

		log.Printf("Map contents:\n%s", s)
	}
}

// formatMapContent prints the content of the map into a string.
func formatMapContent(m *ebpf.Map) (string, error) {
	var (
		sb  strings.Builder
		key bpfSessionKey
		val bpfSessionValue
	)

	iter := m.Iterate()
	for iter.Next(&key, &val) {
		sb.WriteString(fmt.Sprintf("\t%15s:%5d - %15s:%5d Proto:%4s => Ingress:%10d Egress:%10d\n",
			intToIp(key.Saddr), portToLittleEndian(key.Sport),
			intToIp(key.Daddr), portToLittleEndian(key.Dport),
			protoMap[key.Proto], val.InCount, val.EgCount))
	}

	return sb.String(), iter.Err()
}

// intToIp convert an int32 value retrieved from the network traffic (big endian) into a netip.Addr
func intToIp(val uint32) netip.Addr {
	a4 := [4]byte{}
	binary.LittleEndian.PutUint32(a4[:], val)
	return netip.AddrFrom4(a4)
}

// portToLittleEndian convert a uint16 value retrieved from the network traffic (big endian) into a little endian
func portToLittleEndian(val uint16) uint16 {
	p2 := [2]byte{}
	binary.LittleEndian.PutUint16(p2[:], val)
	return binary.LittleEndian.Uint16(p2[:])
}
