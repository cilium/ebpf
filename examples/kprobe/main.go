// This program demonstrates how to attach an eBPF program to a kprobe.
// The program will be attached to the __x64_sys_execve syscall and print out
// the number of times it has been called every second.
package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	goperf "github.com/elastic/go-perf"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 KProbeExample ./bpf/kprobe_example.c -- -I../headers

const mapKey uint32 = 0

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

	// Load Program and Map
	specs, err := NewKProbeExampleSpecs()
	if err != nil {
		log.Fatalf("error while loading specs: %v", err)
	}
	objs, err := specs.Load(nil)
	if err != nil {
		log.Fatalf("error while loading objects: %v", err)
	}

	// Create and attach __x64_sys_execve kprobe
	efd, err := openKProbe("__x64_sys_execve", uint32(objs.ProgramKprobeExecve.FD()))
	if err != nil {
		log.Fatalf("create and attach KProbe: %v", err)

	}
	defer unix.Close(efd)

	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			var value uint64
			if err := objs.MapKprobeMap.Lookup(mapKey, &value); err != nil {
				log.Fatalf("error while reading map: %v", err)
			}
			log.Printf("__x64_sys_execve called %d times\n", value)
		case <-stopper:
			return
		}
	}
}

func openKProbe(syscall string, fd uint32) (int, error) {
	et, err := goperf.LookupEventType("kprobe")
	if err != nil {
		return 0, fmt.Errorf("read PMU type: %v", err)
	}

	config1ptr := newStringPointer(syscall)
	ev, err := goperf.Open(&goperf.Attr{Type: et, Config1: uint64(uintptr(config1ptr))}, goperf.AllThreads, 0, nil)
	if err != nil {
		return 0, fmt.Errorf("perf event open: %v", err)
	}
	efd, err := ev.FD()
	if err != nil {
		return 0, fmt.Errorf("get perf event fd: %v", err)
	}

	// Ensure config1ptr is not finalized until goperf.Open returns.
	runtime.KeepAlive(config1ptr)

	if err := unix.IoctlSetInt(efd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		unix.Close(efd)
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
