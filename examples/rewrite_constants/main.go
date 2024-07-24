package main

import (
	"log"
	"runtime"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/unix"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type key_t bpf bpf.c -- -I../headers

var (
	target_syscall_name string = "execve"
	target_syscall_id   int64  = -1
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

	for range ticker.C {
		var (
			key   bpfKeyT
			count uint64
			pids  []bpfKeyT
		)

		// clear console && print header
		log.Printf("\033[H\033[2J")
		log.Printf("Monitoring syscall_%v\n", target_syscall_name)

		iter := objs.SyscallCountMap.Iterate()
		for iter.Next(&key, &count) {
			log.Printf("comm: %v(pid: %v) called syscall_%v %v times\n", unix.ByteSliceToString(key.Comm[:]), key.Pid, target_syscall_name, count)
			pids = append(pids, key)
		}

		// clear the map
		for _, pid := range pids {
			objs.SyscallCountMap.Delete(&pid)
		}
	}
}
