// +build linux

// This program demonstrates how to attach an eBPF program to a uretprobe.
// The program will be attached to the 'readline' symbol in the binary '/bin/bash' and print out
// the line which 'readline' functions returns to the caller.
package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 UretProbeExample ./bpf/uretprobe_example.c -- -I../headers -O2

type Event struct {
	PID  uint32
	Line [80]byte
}

const (
	bashPath = "/bin/bash"
	symbol   = "readline"
)

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Increase rlimit so the eBPF map and program can be loaded.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %v", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := UretProbeExampleObjects{}
	if err := LoadUretProbeExampleObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Open "/bin/bash" and read its symbols.
	ex, err := link.OpenExecutable(bashPath)
	if err != nil {
		log.Fatalf("open executable: %v", err)
	}

	// Open a Uretprobe at the exit point of the "readline" symbol and attach
	// it to the pre-compiled program.
	up, err := ex.Uretprobe(symbol, objs.UretprobeBashReadline)
	if err != nil {
		log.Fatalf("open uretprobe: %v", err)
	}
	defer up.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("error while creating ringbuffer reader: %v", err)
	}
	defer rd.Close()

	var event Event
	go func() {
		for {
			record, err := rd.Read()
			if err != nil {
				if perf.IsClosed(err) {
					return
				}
				log.Printf("failed to read from ringbuffer: %+v\n", err)
			}
			if record.LostSamples != 0 {
				log.Printf("lost samples due to ringbuffer full: %+v\n", err)
				continue
			}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
				log.Printf("failed to read buffer: %v\n", err)
				continue
			}
			line := string(event.Line[:bytes.IndexByte(event.Line[:], 0)])
			log.Printf("%s from /bin/bash called with %s\n", symbol, line)
		}
	}()

	<-stopper
}
