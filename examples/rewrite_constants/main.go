package main

import (
	"log"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf bpf.c -- -I../headers

const (
	target_syscall_name string = "execve"
	mapKey              uint32 = 0
)

var (
	target_syscall_id int64 = -1
)

func init() {
	// Set the target syscall id based on the architecture.
	switch runtime.GOARCH {
	case "amd64":
		target_syscall_id = 11
	case "arm64":
		target_syscall_id = 221
	default:
		log.Fatalf("unsupported architecture %v", runtime.GOARCH)
	}
}

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		log.Fatal(err)
	}

	// Rewrite the target syscall id in the BPF program.
	if err := spec.RewriteConstants(map[string]interface{}{
		"target_syscall_id": target_syscall_id,
	}); err != nil {
		log.Fatal(err)
	}

	spec.LoadAndAssign(&objs, nil)
	defer objs.Close()

	raw_tp, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.SysEnter,
		AttachType: ebpf.AttachTraceRawTp,
	})
	if err != nil {
		log.Fatalf("attaching raw tracepoint: %v", err)
	}
	defer raw_tp.Close()

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	for range ticker.C {
		var value uint64
		if err := objs.SyscallCountMap.Lookup(mapKey, &value); err != nil {
			log.Fatalf("reading map: %v", err)
		}
		log.Printf("sys_%s called %d times\n", target_syscall_name, value)
	}
}
