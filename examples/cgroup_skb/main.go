//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a control group.
// The eBPF program will be attached as an egress filter for the socket to count the packets.
// It prints the count of total packets every second.
package main

import (
	"errors"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ./bpf/cgroup_skb_example.c -- -I../headers

const (
	mapKey      uint32 = 0
	procFS             = "/proc/mounts"
	bpfProgName        = "count_egress_packets"
)

var cgroup2Mount = struct {
	once sync.Once
	path string
	err  error
}{}

// The /proc/mounts lists the cgroupv2 mount point with the file system type of `cgroup2`
// that makes it convenient for locating the cgroupv2 file system for different systems.
func cgroup2Path() (string, error) {
	cgroup2Mount.once.Do(func() {
		mounts, err := ioutil.ReadFile(procFS)
		if err != nil {
			cgroup2Mount.err = err
			return
		}

		for _, line := range strings.Split(string(mounts), "\n") {
			mount := strings.Split(line, " ")
			if len(mount) >= 3 && mount[2] == "cgroup2" {
				cgroup2Mount.path = mount[1]
				return
			}

			continue
		}

		cgroup2Mount.err = errors.New("cgroup2 not mounted")
	})

	return cgroup2Mount.path, cgroup2Mount.err
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

	// Find the count_egress_packets program.
	bpfProg := objs.CountEgressPackets

	// Get the root cgroup file discriptor.
	cgroupFS, err := cgroup2Path()
	if err != nil {
		log.Fatal(err)
	}
	cgroup, err := os.Open(cgroupFS)
	if err != nil {
		log.Fatal(err)
		return
	}
	defer cgroup.Close()

	// Link the count_egress_packets program to the cgroup.
	_, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupInetEgress,
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
