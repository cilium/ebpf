//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a control group.
// The eBPF program will be attached as an egress filter,
// receiving an `__sk_buff` pointer for each outgoing packet.
// It prints the count of total packets every second.
package main

import (
	"bufio"
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

// $BPF_CLANG, $BPF_STRIP and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -strip $BPF_STRIP -cflags $BPF_CFLAGS bpf ./bpf/cgroup_skb_example.c -- -I../headers

var cgroupPath = ""

func init() {
	// Get the first-mounted cgroupv2 path.
	if err := detectCgroupPath(); err != nil {
		log.Fatal(err)
	}

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

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

	log.Println("Counting packets...")

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)

	for {
		select {
		case <-ticker.C:
			var value uint64
			if err := objs.PktCount.Lookup(uint32(0), &value); err != nil {
				log.Fatalf("reading map: %v", err)
			}
			log.Printf("number of packets: %d\n", value)
		case <-stopper:
			return
		}
	}
}

// detectCgroupPath returns the first-found mount point of type cgroup2
// and stores it in the cgroupPath global variable.
func detectCgroupPath() error {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			cgroupPath = fields[1]
			return nil
		}
		continue
	}

	return errors.New("cgroup2 not mounted")
}
