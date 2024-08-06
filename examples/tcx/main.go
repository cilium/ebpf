//go:build linux

// This program demonstrates attaching an eBPF program to a network interface
// with Linux TCX (Traffic Control with eBPF). The program counts ingress and egress
// packets using two variables. The userspace program (Go code in this file)
// prints the contents of the two variables to stdout every second.
// This example depends on tcx bpf_link, available in Linux kernel version 6.6 or newer.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags linux bpf tcx.c -- -I../headers
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

	// Print the contents of the counters maps.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		s, err := formatCounters(objs.IngressPktCount, objs.EgressPktCount)
		if err != nil {
			log.Printf("Error reading map: %s", err)
			continue
		}

		log.Printf("Packet Count: %s\n", s)
	}
}

func formatCounters(ingressVar, egressVar *ebpf.Variable) (string, error) {
	var (
		ingressPacketCount uint64
		egressPacketCount  uint64
	)

	// retrieve value from the ingress map
	if err := ingressVar.Get(&ingressPacketCount); err != nil {
		return "", err
	}

	// retrieve value from the egress map
	if err := egressVar.Get(&egressPacketCount); err != nil {
		return "", err
	}

	return fmt.Sprintf("%10v Ingress, %10v Egress", ingressPacketCount, egressPacketCount), nil
}
