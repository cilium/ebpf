// +build linux

// This program demonstrates loading and attaching a CO-RE eBPF program.
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"inet.af/netaddr"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -cc clang-11 bpf ./bpf/core_example.c -- -nostdinc -Wall -Werror -I../headers

type event struct {
	src   netaddr.IP
	dest  netaddr.IP
	state State
}

func (e *event) UnmarshalBytes(data []byte) error {
	var src, dest [16]byte
	copy(src[:], data[:16])
	copy(dest[:], data[16:32])
	e.src = netaddr.IPFrom16(src)
	e.dest = netaddr.IPFrom16(dest)
	e.state = State(binary.BigEndian.Uint16([]byte{0, data[32]}))
	return nil
}

func (e event) String() string {
	return fmt.Sprintf("State: %s, Source: %s, Destination: %s", e.state, e.src, e.dest)
}

func main() {
	// Name of the kernel function to trace.
	fn := "__neigh_event_send"

	// Subscribe to signals for terminating the program.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Remove memlock so that we have room for our map.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memlock: %v", err)
	}

	// Load all the bpf objects (programs, maps, etc...)
	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Link (attach) the kprobe program to the specified function
	kp, err := link.Kprobe(fn, objs.KprobeNeighEventSend)
	if err != nil {
		log.Fatalf("opening kprobe: %s", err)
	}
	defer kp.Close()

	// Initialise the user-space perf-event reader
	rd, err := perf.NewReader(objs.Pipe, 10)
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}
	defer rd.Close()

	events := make(chan event)
	errors := make(chan error)
	for {
		// We don't want to block on the perf Read() call
		go func() {
			perfEvent, err := rd.Read()
			if err != nil {
				errors <- err
				return
			}

			event := event{}
			if err := event.UnmarshalBytes(perfEvent.RawSample); err != nil {
				errors <- err
				return
			}

			events <- event
		}()

		// We want to receive events on a channel, so we can select on it
		select {
		case <-ctx.Done():
			rd.Close()
			return
		case err := <-errors:
			if perf.IsClosed(err) {
				return
			}
			log.Printf("reading from perf event buffer: %s", err)
			continue
		case event := <-events:
			log.Printf("neighbour event: %s", event)
		}
	}
}
