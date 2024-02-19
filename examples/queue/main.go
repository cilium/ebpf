// This program demonstrates attaching an eBPF program to a network interface
// with XDP (eXpress Data Path). The program parses the IPv4 source address
// from packets and pushes the address alongside the computed packet arrival timestamp
// into a Queue. This is just an example and probably does not represent the most
// efficient way to perform such a task. Another potential solution would be to use
// an HashMap with a small __u64 arrays associated to each IPv4 address (key).
// In both the two ways it is possible to lose some packet if (a) queue is not large
// enough or the packet processing time is slow or (b) if the associated array is
// smaller than the actual received packet from an address.
// The userspace program (Go code in this file) prints the contents
// of the map to stdout every second, parsing the raw structure into a human-readable
// IPv4 address and Unix timestamp.
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
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf xdp.c -- -I../headers

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

	// Attach the program.
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("could not attach XDP program: %s", err)
	}
	defer l.Close()

	log.Printf("Attached XDP program to iface %q (index %d)", iface.Name, iface.Index)
	log.Printf("Press Ctrl-C to exit and remove the program")

	// Retrieve boot time once, and use it for every later ktime conversions
	bootTime := getSysBoot()

	// Print the contents of the BPF queue (packet source IP address and timestamp).
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatMapContents(objs.QueueWithData, bootTime)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}
		log.Printf("Map contents:\n%s", s)
	}
}

// formatMapContents formats an output string with the content of the provided map.
//
// For each entry, the function outputs a line containing the human-readable IPv4 address
// retrieved from the packet structure formatted and the converted ktime_ns into Unix Time
//
// In case of error or empty map, the function returns the corresponding error.
func formatMapContents(m *ebpf.Map, bootTime time.Time) (string, error) {
	var (
		sb  strings.Builder
		val bpfPacketData
	)
	iter := m.Iterate()
	for iter.Next(nil, &val) {
		// Convert the __u32 into human-readable IPv4
		a4 := [4]byte{}
		binary.LittleEndian.PutUint32(a4[:], val.SrcIp)
		addr := netip.AddrFrom4(a4)

		// Convert ktime timestamp into Time struct, adding the retrieved
		// timestamp to the previously computer boot time
		t := bootTime.Add(time.Duration(val.Timestamp) * time.Nanosecond)

		sb.WriteString(fmt.Sprintf("\t%s - %s\n", addr, t))
	}
	return sb.String(), iter.Err()
}

// Retrieve system boot time and convert it into Time struct
func getSysBoot() time.Time {
	sysInfo := &syscall.Sysinfo_t{}
	syscall.Sysinfo(sysInfo)
	return time.Now().Add(-time.Duration(sysInfo.Uptime) * time.Second)
}
