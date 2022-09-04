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
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"os"
	"time"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf bpf/tcplife.c -- -I../headers

const (
	name  = "inet_sock_set_state"
	group = "sock"
)

type CommandArgs struct {
	EmitTimestamp *bool
	Verbose       *bool
}

func main() {
	app := &cli.App{
		Name: "tcplife",
		Usage: `Trace the lifespan of TCP sessions and summarize.
USAGE: tcplife [-h] [-p PID] [-4] [-6] [-L] [-D]
EXAMPLES:
    tcplife -p 1215             # only trace PID 1215
    tcplife -p 1215 -4          # trace IPv4 only`,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "pid",
				Aliases: []string{"p"},
				EnvVars: []string{"PID"},
				Value:   "0",
				Usage:   "Process ID to trace",
			},
			&cli.BoolFlag{
				Name:    "ipv4",
				Aliases: []string{"4"},
				Usage:   "Trace IPv4 only",
			},
			&cli.BoolFlag{
				Name:    "ipv6",
				Aliases: []string{"6"},
				Usage:   "Trace IPv6 only",
			},
			&cli.IntSliceFlag{
				Name:    "localport",
				Aliases: []string{"L"},
				EnvVars: []string{"LOCALPORT"},
				Usage:   "Comma-separated list of local ports to trace.",
			},
			&cli.IntSliceFlag{
				Name:    "remoteport",
				Aliases: []string{"D"},
				EnvVars: []string{"REMOTEPORT"},
				Usage:   "Comma-separated list of remote ports to trace.",
			},
		},
		Action: func(cCtx *cli.Context) error {
			args := CommandArgs{}
			consts := map[string]interface{}{}
			if cCtx.Uint64("pid") != 0 {
				consts["target_pid"] = cCtx.Uint64("pid")
			}
			if !(cCtx.Bool("ipv4") && cCtx.Bool("ipv6")) {
				if cCtx.Bool("ipv4") {
					consts["target_family"] = unix.AF_INET
				} else if cCtx.Bool("ipv6") {
					consts["target_family"] = unix.AF_INET6
				}
			}
			if cCtx.IntSlice("localport") != nil {
				consts["target_dports"] = cCtx.IntSlice("localport")
			}
			if cCtx.IntSlice("remoteport") != nil {
				consts["target_sports"] = cCtx.IntSlice("remoteport")
			}
			if cCtx.Bool("time") {
				timeVar := cCtx.Bool("time")
				args.EmitTimestamp = &timeVar
			}

			return TCPLife(args, consts)
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func TCPLife(args CommandArgs, consts map[string]interface{}) error {
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
	obj := bpfObjects{}
	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("loading objects: %v", err)
		return err
	}
	if len(consts) > 0 {
		spec.RewriteConstants(consts)
	}
	err = spec.LoadAndAssign(&obj, nil)
	if err != nil {
		log.Fatalf("load and assing: %v", err)
		return err
	}
	defer obj.Close()

	kp, err := link.Tracepoint(group, name, obj.InetSockSetState, nil)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer kp.Close()

	log.Println("Waiting for events..")
	rd, err := perf.NewReader(obj.Events, os.Getpagesize())
	if err != nil {
		log.Fatalf("creating event reader: %s", err)
	}
	defer rd.Close()
	fmt.Printf("%7s %16s %26s %5s %26s %5s %6s %6s %6s\n",
		"PID", "COMM", "LADDR", "LPORT", "RADDR", "RPORT",
		"TX_KB", "RX_KB", "MS")
	for {
		record, err := rd.Read()
		//var ip, value uint32
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				log.Println("Received signal, exiting..")
				return nil
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
		fmt.Println("\ncurrent_time:", time.UnixMicro(int64(event.TsUs)).Format("2006-01-02 15:04:05"))
		if event.Family == unix.AF_INET6 {
			daddr = daddr_buf.Bytes()
			saddr = saddr_buf.Bytes()
			fmt.Printf("%7d %20s %26s %5d %26s %5d %6d %6d %6d\n",
				event.Pid, comm, saddr.To16(), event.Sport,
				daddr.To16(), event.Dport, event.TxB/1024, event.RxB/1024, event.SpanUs/1000)
		} else {
			saddr = saddr_buf.Bytes()[:4]
			daddr = daddr_buf.Bytes()[:4]
			fmt.Printf("%7d %20s %26s %5d %26s %5d %6d %6d %6d\n",
				event.Pid, comm, saddr.To4(), event.Sport,
				daddr.To4(), event.Dport, event.TxB/1024, event.RxB/1024, event.SpanUs/1000)
		}
	}
	return nil
}
