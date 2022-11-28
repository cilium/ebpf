// This program demonstrates how to attach an uprobe of golang.
// The obj/obj is compiled with go1.16. For go1.17 and later, will be added later.

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"os"
	"os/signal"
	"path"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target native -type event bpf uprobe.c -- -I../headers

func main() {
	// Path of user exec file
	dir, err := os.Getwd()
	if err != nil {
		log.Fatalf("get current work dir failed, %s", err.Error())
	}
	exec := path.Join(dir, "./obj/obj")

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err.Error())
	}
	defer objs.Close()

	ex, err := link.OpenExecutable(exec)
	if err != nil {
		log.Fatalf("opening executable failed, %s: %s", exec, err.Error())
	}

	up, err := ex.Uprobe("main.Print", objs.UprobeMainPrint, nil)
	if err != nil {
		log.Fatalf("create uprobe failed, %s", err.Error())
	}
	defer up.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("createing perf event reader: %s", err.Error())
	}
	defer rd.Close()

	go func() {
		<-stopper
		log.Println("Received signal, exiting program...")

		if err := rd.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err.Error())
		}
	}()

	log.Printf("Listening for events..\n")

	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			log.Printf("Reading from perf event reader: %s", err.Error())
			continue
		}
		if record.LostSamples != 0 {
			log.Printf("Perf event ring buffer full, dropped %d samples",
				record.LostSamples)
			continue
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample),
			binary.LittleEndian, &event); err != nil {
			log.Printf("parsing perf event: %s\n", err)
			continue
		}

		arg0Len := int(event.Arg0Length)
		if arg0Len > len(event.Arg0) {
			log.Printf("Go argument longer than 100, %d\n", arg0Len)
			continue
		}
		arg0 := string(event.Arg0[:arg0Len])
		log.Printf("Get golang arg: %s\n", arg0)
	}
}
