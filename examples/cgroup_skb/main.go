//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a control group.
// The eBPF program will be attached as an egress filter for the socket to count the packets.
// It prints the count of total packets every second.
package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ./bpf/cgroup_skb_example.c -- -I../headers

const mapKey uint32 = 0

const (
	cgroupFS    = "/sys/fs/cgroup/unified"
	bpfFS       = "/sys/fs/bpf"
	bpfProgName = "count_egress_packets"
)

func main() {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Find the count_egress_packets program and the BPF VFS path where the
	// program will persist.
	bpfProg := objs.CountEgressPackets
	pinPath := filepath.Join(bpfFS, bpfProgName)
	// Pin the program. Make sure the Close is being called.
	bpfProg.Pin(pinPath)

	// Get root cgroup file discriptor.
	cgroup, err := os.Open(cgroupFS)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer cgroup.Close()

	// Link the count_egress_packets program to the cgroup.
	_, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: bpfProg,
	})
	if err != nil {
		log.Fatal(err)
		return
	}
	// Unloads the program.
	defer bpfProg.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)

	log.Println("counting packets")

	for {
		select {
		case <-ticker.C:
			var value uint64
			if err := objs.SkbMap.Lookup(mapKey, &value); err != nil {
				log.Fatalf("reading map: %v", err)
			}
			log.Printf("number of packets: %d\n", value)
		case <-stopper:
			return
		}
	}
}
