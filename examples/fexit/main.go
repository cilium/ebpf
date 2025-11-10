//go:build linux

// This program demonstrates attaching a fexit eBPF program to a kernel function.
// It's designed to test error handling when attaching fexit programs on systems
// with different kernel configurations.
//
// The program attaches to vfs_read, which is called when data is read from files.
//
// fexit requires:
//   - Kernel 5.5+ (for BPF trampoline support)
//   - CONFIG_DEBUG_INFO_BTF=y (BTF support)
//   - ftrace enabled (CONFIG_FTRACE=y and runtime enabled)
//
// Usage:
//
//	On a properly configured kernel:
//	  $ go run -exec sudo .
//	  Successfully attached fexit program to vfs_read
//	  Monitoring file reads (Ctrl+C to exit)...
//	  [Check /sys/kernel/debug/tracing/trace_pipe for output]
//
//	On a kernel without ftrace or fexit support:
//	  $ go run -exec sudo .
//	  Error: Failed to attach fexit program: create TraceFExit tracing link: ...
//
// This example is useful for testing that error messages clearly indicate
// the attach type (fexit) rather than showing misleading "raw tracepoint" errors.
package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 bpf fexit.c -- -I../headers

func main() {
	// Subscribe to signals for terminating the program.
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock: %v", err)
	}

	// Load pre-compiled eBPF programs into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach the fexit program to vfs_read kernel function.
	// This is where we test the improved error messaging.
	// On kernels without fexit support, you should see:
	//   "create TraceFExit tracing link: ..."
	// instead of the old misleading:
	//   "create raw tracepoint: ..."
	//
	// Note: Explicitly setting AttachType is recommended for clearer error messages.
	lnk, err := link.AttachTracing(link.TracingOptions{
		Program:    objs.VfsReadExit,
		AttachType: ebpf.AttachTraceFExit,
	})
	if err != nil {
		log.Fatalf("Failed to attach fexit program: %v", err)
	}
	defer lnk.Close()

	log.Println("Successfully attached fexit program to vfs_read")
	log.Println("Monitoring file reads (Ctrl+C to exit)...")
	log.Println("To see output: sudo cat /sys/kernel/debug/tracing/trace_pipe")
	log.Println("")
	log.Println("Try reading a file in another terminal to trigger the fexit program:")
	log.Println("  $ cat /etc/hostname")

	// Wait a bit to show we're running
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			log.Println("fexit program still running...")
		case <-stopper:
			log.Println("Received signal, exiting...")
			return
		}
	}
}
