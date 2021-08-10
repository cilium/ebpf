// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 KProbePinExample ./bpf/kprobe_pin_example.c -- -I../headers

const (
	mapKey    uint32 = 0
	bpfFSPath        = "/sys/fs/bpf"
)

func main() {

	// Name of the kernel function to trace.
	fn := "sys_execve"

	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Increase the rlimit of the current process to provide sufficient space
	// for locking memory for the eBPF map.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}

	var kProbeObj KProbePinExampleObjects
	if err := LoadKProbePinExampleObjects(&kProbeObj, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: bpfFSPath,
		},
		Programs: ebpf.ProgramOptions{
			LogLevel: 1,
		},
	}); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	// Open a Kprobe at the entry point of the kernel function and attach the
	// pre-compiled program. Each time the kernel function enters, the program
	// will increment the execution counter by 1. The read loop below polls this
	// map value once per second.
	kp, err := link.Kprobe(fn, kProbeObj.KprobeExecve)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// // Read loop reporting the total amount of times the kernel
	// // function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)

	log.Println("Waiting for events..")

	for {
		select {
		case <-ticker.C:
			var value uint64
			if err := kProbeObj.KprobeMap.Lookup(mapKey, &value); err != nil {
				log.Fatalf("reading map: %v", err)
			}
			log.Printf("%s called %d times\n", fn, value)
		case <-stopper:
			return
		}
	}
}
