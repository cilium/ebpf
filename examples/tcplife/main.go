// This program demonstrates attaching an eBPF program to a kernel tracepoint.
// The eBPF program will be attached to the page allocation tracepoint and
// prints out the number of times it has been reached. The tracepoint fields
// are printed into /sys/kernel/debug/tracing/trace_pipe.
package main

import (
	"C"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os"
	"time"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf bpf/tcplife.c -- -I../headers

var rootCmd = &cobra.Command{
	Use:   "tcplife",
	Short: "Trace the lifespan of TCP sessions and summarize.",
	Long: `Trace the lifespan of TCP sessions and summarize.\n\n
		USAGE: tcplife [-h] [-p PID] [-4] [-6] [-L] [-D] [-T] [-w]\n\n
		EXAMPLES:\n
			tcplife -p 1215             # only trace PID 1215\n
			tcplife -p 1215 -4          # trace IPv4 only\n
		   `,
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			fmt.Println(r)
		}
	}()
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

	// Open a tracepoint and attach the pre-compiled program. Each time
	// the kernel function enters, the program will increment the execution
	// counter by 1. The read loop below polls this map value once per
	// second.
	// The first two arguments are taken from the following pathname:
	// /sys/kernel/debug/tracing/events/kmem/mm_page_alloc
	kp, err := link.Tracepoint("sock", "inet_sock_set_state", objs.InetSockSetState, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")
	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()
	fmt.Printf("%7s %16s %26s %5s %26s %5s %6s %6s %s\n",
		"PID", "COMM", "LADDR", "LPORT", "RADDR", "RPORT",
		"TX_KB", "RX_KB", "MS")
	for {
		record, err := rd.Read()
		//var ip, value uint32
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return
			}
			log.Printf("reading from reader: %s", err)
			continue
		}
		var event bpfEvent
		// Parse the ringbuf event entry into a bpfEvent structure.
		if err := binary.Read(bytes.NewBuffer(record.RawSample), internal.NativeEndian, &event); err != nil {
			log.Printf("parsing ringbuf event: %s", err)
			continue
		}
		saddr_buf, daddr_buf, comm := bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{}), bytes.NewBuffer([]byte{})
		binary.Write(saddr_buf, binary.LittleEndian, event.Saddr)
		binary.Write(daddr_buf, binary.LittleEndian, event.Daddr)
		binary.Write(comm, binary.LittleEndian, event.Comm)
		var saddr net.IP
		var daddr net.IP
		if event.Family == unix.AF_INET6 {
			daddr = daddr_buf.Bytes()
			saddr = saddr_buf.Bytes()
			fmt.Printf("%7d %20s %26s %5d %26s %5d %6d %6d %d\n",
				event.Pid, comm, saddr.To16(), event.Sport,
				daddr.To16(), event.Dport, event.TxB, event.RxB, event.TsUs)
		} else {
			saddr = saddr_buf.Bytes()[:4]
			daddr = daddr_buf.Bytes()[:4]
			fmt.Printf("%7d %20s %26s %5d %26s %5d %6d %6d %d\n",
				event.Pid, comm, saddr.To4(), event.Sport,
				daddr.To4(), event.Dport, event.TxB, event.RxB, event.TsUs)
		}
	}
}
