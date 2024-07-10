// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"log"
	"strings"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf kprobe.c -- -I../headers

const (
	mapKey    uint32 = 0
	Kprobe    string = "kprobe"
	Kretprobe string = "kretprobe"
)

// getKprobeKind returns the kind of kprobe based on the sectionName.
func getKprobeKind(sectionName string) string {
	split := strings.Split(sectionName, "/")
	if len(split) != 2 {
		return ""
	}

	switch split[0] {
	case Kprobe:
		return Kprobe
	case Kretprobe:
		return Kretprobe
	default:
		return ""
	}
}

func main() {

	// Name of the kernel function to trace.
	fn := "sys_execve"

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("loading bpf: %v", err)
	}

	if err = spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	defer objs.Close()

	// Get kprobe ProgramInfo
	info, err := objs.KprobeExecve.Info()
	if err != nil {
		log.Fatalf("getting kprobe info: %v", err)
	}

	var kp link.Link
	var count int
	for _, programSpec := range spec.Programs {
		// Skip if the program name is not the same as the kprobe name
		if programSpec.Name != info.Name {
			continue
		}

		kind := getKprobeKind(programSpec.SectionName)
		switch kind {
		case Kprobe:
			// Open a Kprobe at the entry point of the kernel function and attach the
			// pre-compiled program. Each time the kernel function enters, the program
			// will increment the execution counter by 1. The read loop below polls this
			// map value once per second.
			kp, err = link.Kprobe(fn, objs.KprobeExecve, nil)
			if err != nil {
				log.Fatalf("opening kprobe: %s", err)
			}
		case Kretprobe:
			kp, err = link.Kretprobe(fn, objs.KprobeExecve, nil)
			if err != nil {
				log.Fatalf("opening kretprobe: %s", err)
			}
		default:
			log.Fatalf("invalid kprobe kind: %s", programSpec.SectionName)
		}

		count++
	}

	if count == 0 {
		log.Fatalf("no kprobe found for %s", fn)
	}

	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	for range ticker.C {
		var value uint64
		if err := objs.KprobeMap.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("%s called %d times\n", fn, value)
	}
}
