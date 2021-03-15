// This program demonstrates how to attach an eBPF program to a uretprobe.
// The program will be attached to the 'readline' symbol in the binary '/bin/bash' and print out
// the line which 'readline' functions returns to the caller.
package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"unsafe"

	ringbuffer "github.com/cilium/ebpf/perf"
	goperf "github.com/elastic/go-perf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 UProbeExample ./bpf/uprobe_example.c -- -I../headers -O2

const bashPath = "/bin/bash"
const symbolName = "readline"

type Event struct {
	PID  uint32
	Line [80]byte
}

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

	specs, err := NewUProbeExampleSpecs()
	if err != nil {
		log.Fatalf("error while loading specs: %v", err)
	}

	objs, err := specs.Load(nil)
	if err != nil {
		log.Fatalf("error while loading objects: %v", err)
	}

	symbolAddress, err := getSymbolAddress(bashPath, symbolName)
	if err != nil {
		log.Fatalf("error while getting symbol address: %v", err)
	}

	efd, err := openUProbe(bashPath, symbolAddress, true, uint32(objs.ProgramUprobeBashReadline.FD()))
	if err != nil {
		log.Fatalf("create and attach UProbe: %v", err)

	}
	defer unix.Close(efd)

	rd, err := ringbuffer.NewReader(objs.MapEvents, os.Getpagesize())
	if err != nil {
		log.Fatalf("error while creating ringbuffer reader: %v", err)
	}
	defer func() {
		<-stopper
		_ = rd.Close()
	}()

	var event Event
	for {
		select {
		case <-stopper:
			return
		default:
		}
		record, err := rd.Read()
		if err != nil {
			if ringbuffer.IsClosed(err) {
				return
			}
			log.Printf("failed to read from ringbuffer: %+v\n", err)
		}
		if record.LostSamples != 0 {
			log.Printf("lost samples due to ringbuffer full: %+v\n", err)
			continue
		}
		binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)
		line := string(event.Line[:bytes.IndexByte(event.Line[:], 0)])
		log.Printf("%s from /bin/bash called with %s\n", symbolName, line)
	}
}

func openUProbe(binaryPath string, symbolAddress uint64, isReturn bool, fd uint32) (int, error) {
	et, err := goperf.LookupEventType("uprobe")
	if err != nil {
		return 0, fmt.Errorf("read PMU type: %v", err)
	}

	config1ptr := newStringPointer(binaryPath)

	attr := goperf.Attr{
		Type:    et,
		Config1: uint64(uintptr(config1ptr)),
		Config2: symbolAddress,
	}
	if isReturn {
		// set uretprobe bit
		attr.Config |= 1 << 0
	}
	ev, err := goperf.Open(&attr, goperf.AllThreads, 0, nil)
	if err != nil {
		return 0, fmt.Errorf("perf event open: %v", err)
	}
	efd, err := ev.FD()
	if err != nil {
		return 0, fmt.Errorf("get perf event fd: %v", err)
	}

	// Ensure config1ptr is not finalized until goperf.Open returns.
	runtime.KeepAlive(config1ptr)

	if err := ev.Enable(); err != nil {
		_ = unix.Close(efd)
		return 0, fmt.Errorf("perf event enable: %v", err)
	}

	if err := ev.SetBPF(fd); err != nil {
		unix.Close(efd)
		return 0, fmt.Errorf("perf event set bpf: %v", err)
	}

	return efd, nil
}

func newStringPointer(str string) unsafe.Pointer {
	// The kernel expects strings to be zero terminated
	buf := make([]byte, len(str)+1)
	copy(buf, str)
	return unsafe.Pointer(&buf[0])
}

func getSymbolAddress(elfPath, symbolName string) (uint64, error) {
	binFile, err := elf.Open(elfPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open ELF: %+v", err)
	}
	defer func() {
		_ = binFile.Close()
	}()

	syms, err := binFile.DynamicSymbols()
	if err != nil {
		return 0, fmt.Errorf("failed to list symbols: %+v", err)
	}

	for _, sym := range syms {
		if sym.Name == symbolName {
			return sym.Value, nil
		}
	}

	return 0, fmt.Errorf("failed to find symbol %s", symbolName)
}
