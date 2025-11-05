//go:build linux

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go tool bpf2go -no-global-types -tags linux bpf sched_ext.c -- -I../headers/

// Load a minimal defining sched_ext_ops map
//
// After run this program, you can find the current status of the BPF scheduler can be determined as follows:
//
//	# cat /sys/kernel/sched_ext/state
//	enabled
//	# cat /sys/kernel/sched_ext/root/ops
//	miminal
func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	m := objs.MinimalSched
	l, err := link.AttachStructOps(link.StructOpsOptions{Map: m})
	if err != nil {
		log.Fatalf("failed to attach sched_ext: %s", err)
	}
	defer l.Close()

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	<-stopper

	log.Print("quit sched_ext")
}
