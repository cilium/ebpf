//go:build linux
// +build linux

// This program demonstrates attaching a fentry eBPF program to
// tcp_connect. It prints the command/IPs/ports information
// once the host sent a TCP SYN packet to a destination.
// It supports IPv4 at this example.
//
// Sample output:
//
// examples# go run -exec sudo ./fentry
// 2021/11/06 17:51:15 Comm   Src addr      Port   -> Dest addr        Port
// 2021/11/06 17:51:25 wget   10.0.2.15     49850  -> 142.250.72.228   443
// 2021/11/06 17:51:46 ssh    10.0.2.15     58854  -> 10.0.2.1         22
// 2021/11/06 18:13:15 curl   10.0.2.15     54268  -> 104.21.1.217     80

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf ./bpf/fentry_example.c -- -I../headers

// Length of struct event_t sent from kernelspace.
var eventLength = 28

type Event struct {
	Comm  string
	SPort uint16
	DPort uint16
	SAddr uint32
	DAddr uint32
}

// UnmarshalBinary unmarshals a ringbuf record into an Event.
func (e *Event) UnmarshalBinary(b []byte) error {
	if len(b) != eventLength {
		return fmt.Errorf("unexpected event length %d", len(b))
	}

	e.Comm = unix.ByteSliceToString(b[:16])

	e.SPort = internal.NativeEndian.Uint16(b[16:18])
	e.DPort = binary.BigEndian.Uint16(b[18:20])

	e.SAddr = binary.BigEndian.Uint32(b[20:24])
	e.DAddr = binary.BigEndian.Uint32(b[24:28])

	return nil
}

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

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

	link, err := link.AttachTrace(link.TraceOptions{
		Program: objs.bpfPrograms.TcpConnect,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	go func() {
		<-stopper

		if err := rd.Close(); err != nil {
			log.Fatalf("closing ringbuf reader: %s", err)
		}
	}()

	log.Printf("%-16s %-15s %-6s -> %-15s %-6s",
		"Comm",
		"Src addr",
		"Port",
		"Dest addr",
		"Port",
	)

	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}

		// Parse the ringbuf event entry into an Event structure.
		if err := event.UnmarshalBinary(record.RawSample); err != nil {
			log.Fatal("unmarshaling event: %s", err)
		}

		log.Printf("%-16s %-15s %-6d -> %-15s %-6d",
			event.Comm,
			intToIP(event.SAddr),
			event.SPort,
			intToIP(event.DAddr),
			event.DPort,
		)
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipNum)
	return ip
}
