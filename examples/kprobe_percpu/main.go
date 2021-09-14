//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol and
// using percpu map to collect data. The eBPF program will be attached to the
// start of the sys_execve kernel function and prints out the number of called
// times on each cpu every second.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 KProbeExample ./bpf/kprobe_percpu_example.c -- -nostdinc -I../headers

const mapKey uint32 = 0

func main() {

	// Name of the kernel function to trace.
	fn := "sys_execve"

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Increase the rlimit of the current process to provide sufficient space
	// for locking memory for the eBPF map.
	_, err := ebpf.RemoveMemlockRlimit()
	if err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := KProbeExampleObjects{}
	if err := LoadKProbeExampleObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(fn, objs.KprobeExecve)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)

	log.Println("Waiting for events..")

	for {
		select {
		case <-ticker.C:
			var all_cpu_value []uint64
			if err := objs.KprobeMap.Lookup(mapKey, &all_cpu_value); err != nil {
				log.Fatalf("reading map: %v", err)
			}
			for cpuid, cpuvalue := range all_cpu_value {
				log.Printf("%s called %d times on CPU%v\n", fn, cpuvalue, cpuid)
			}
			log.Printf("\n")
		case <-stopper:
			return
		}
	}
}
