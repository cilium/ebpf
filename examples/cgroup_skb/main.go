//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a control group.
// The eBPF program will be attached as an egress filter, receiving an `__sk_buff` pointer for each outgoing packet.
// It prints the count of total packets every second.
package main

import (
	"errors"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ./bpf/cgroup_skb_example.c -- -I../headers

const (
	mapKey uint32 = 0
	procFS        = "/proc/mounts"
)

var cgroupPath = ""

// The /proc/mounts lists the cgroupv2 mount point with the file system type of `cgroup2`
// that makes it convenient for locating the cgroupv2 file system for different systems.
func cgroup2Path() (string, error) {
	mounts, err := os.ReadFile(procFS)
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(mounts), "\n") {
		// example mount: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		mount := strings.Split(line, " ")
		if len(mount) >= 3 && mount[2] == "cgroup2" {
			return mount[1], nil
		}
		continue
	}

	return "", errors.New("cgroup2 not mounted")
}

func init() {
	// Get the root cgroupv2 file discriptor.
	cgroupFS, err := cgroup2Path()
	if err != nil {
		log.Fatal(err)
	}
	cgroup, err := os.Open(cgroupFS)
	if err != nil {
		log.Fatal(err)
	}
	defer cgroup.Close()

	cgroupPath = cgroup.Name()
}

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

	// Link the count_egress_packets program to the cgroup.
	l, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.CountEgressPackets,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)

	log.Println("counting packets")

	for {
		select {
		case <-ticker.C:
			var value uint64
			if err := objs.PktCount.Lookup(mapKey, &value); err != nil {
				log.Fatalf("reading map: %v", err)
			}
			log.Printf("number of packets: %d\n", value)
		case <-stopper:
			return
		}
	}
}
