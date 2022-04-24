//go:build linux
// +build linux

// This program demonstrates attaching fentry eBPF programs to
// tcp_v4_connect and tcp_rcv_state_process to calculate TCP connect
// latency using CO-RE helpers.
// It prints the IPs/ports/Latency information once a TCP connection is
// established. Current example only supports IPv4.
//
// Sample output:
//
// examples# go run -exec sudo ./tcpconnlat
// 2022/04/24 15:10:05 Attaching BPF program TcpRcvStateProcess Tracing(tcp_rcv_state_process)#6
// 2022/04/24 15:10:05 Attaching BPF program TcpV4Connect Tracing(tcp_v4_connect)#10
// 2022/04/24 15:10:05 Src addr        Port   -> Dest addr       Port   Latency (us)
// 2022/04/24 15:10:15 10.0.2.15       63695  -> 93.184.216.34   20480  173441
// 2022/04/24 15:10:25 127.0.0.1       51334  -> 127.0.0.1       40975  45
// 2022/04/24 15:10:37 10.0.2.15       2704   -> 45.251.106.207  20480  2305

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event bpf tcpconnlat.c -- -I../headers

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
		log.Fatalf("Load BPF objects failed: %v", err)
	}
	defer objs.Close()

	// Attach all BPF programs defined in bpfPrograms
	progTypes := reflect.TypeOf(objs.bpfPrograms)
	progValues := reflect.ValueOf(objs.bpfPrograms)
	for i := 0; i < progValues.NumField(); i++ {
		progType := progTypes.Field(i)
		progValue := progValues.Field(i)
		log.Printf("Attaching BPF program %s %v\n", progType.Name, progValue)

		prog := progValue.Interface().(*ebpf.Program)
		lk, err := link.AttachTracing(link.TracingOptions{Program: prog})
		if err != nil {
			log.Fatal(err)
		}

		defer lk.Close()
	}

	rd, err := ringbuf.NewReader(objs.bpfMaps.Events)
	if err != nil {
		log.Fatalf("Open ringbuf reader failed: %s", err)
	}
	defer rd.Close()

	log.Printf("%-15s %-6s -> %-15s %-6s %-15s",
		"Src addr",
		"Port",
		"Dest addr",
		"Port",
		"Latency (us)",
	)
	go readLoop(rd)

	// Wait
	<-stopper
}

func readLoop(rd *ringbuf.Reader) {
	var event bpfEvent
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}

			log.Printf("Read from reader failed: %s", err)
			continue
		}

		// Parse ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), internal.NativeEndian, &event); err != nil {
			log.Printf("Parse ringbuf event failed: %s", err)
			continue
		}

		log.Printf("%-15s %-6d -> %-15s %-6d %d",
			intToIP(event.Saddr),
			event.Sport,
			intToIP(event.Daddr),
			event.Dport,
			event.LatencyUs,
		)
	}
}

// intToIP converts IPv4 number to net.IP
func intToIP(ipNum uint32) net.IP {
	ip := make(net.IP, 4)
	internal.NativeEndian.PutUint32(ip, ipNum)
	return ip
}
