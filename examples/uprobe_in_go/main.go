// This program demonstrates how to attach an uprobe of golang.
// example works before go1.17.

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf uprobe.c -- -I../headers

func main() {
	// Path of user exec file
	exec := "./obj/obj"

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", er)
	}
	defer objs.Close()

	ex, err := link.OpenExecutable(exec)
	if err != nil {
		log.Fatalf("opening executable failed, %s: %s", exec, err.Error())
	}
}
