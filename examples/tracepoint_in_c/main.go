// This program demonstrates attaching an eBPF program to a kernel tracepoint.
// The eBPF program will be attached to the page allocation tracepoint and
// prints out the number of times it has been reached. The tracepoint fields
// are printed into /sys/kernel/tracing/trace_pipe.
package main

import (
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tracepoint.c -- -I../headers

const mapKey uint32 = 0

func main() {
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

	// Open a tracepoint and attach the pre-compiled program. Each time
	// the kernel function enters, the program will increment the execution
	// counter by 1. The read loop below polls this map value once per
	// second.
	// The first two arguments are taken from the following pathname:
	// /sys/kernel/tracing/events/kmem/mm_page_alloc
	kp, err := link.Tracepoint("kmem", "mm_page_alloc", objs.MmPageAlloc, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
	for range ticker.C {
		var value uint64
		if err := objs.CountingMap.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("%v times", value)
	}
}
