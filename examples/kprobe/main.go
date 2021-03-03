// This program demonstrates how to attach an eBPF program to a kprobe.
// The program will be attached to the __x64_sys_execve syscall and print out
// the number of times it has been called every second.
package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 KProbeExample ./bpf/kprobe_example.c

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
	closer, err := openKProbe("__x64_sys_execve", objs.ProgramKprobeExecve.FD())
	if err != nil {
		log.Fatalf("create and attach KProbe: %v", err)

	}
	defer closer()

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

func openKProbe(syscall string, fd int) (func(), error) {
	t, err := pmuType()
	if err != nil {
		return nil, fmt.Errorf("read PMU type: %v", err)
	}

	efd, err := unix.PerfEventOpen(
		&unix.PerfEventAttr{
			Type: t,
			Ext1: uint64(newStringPointer(syscall)),
		}, //attr
		-1,                        // pid
		0,                         // cpu
		-1,                        // group_fd
		unix.PERF_FLAG_FD_CLOEXEC, // flags
	)
	if err != nil {
		return nil, fmt.Errorf("perf event open: %v", err)
	}

	if err := unix.IoctlSetInt(efd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		unix.Close(efd)
		return nil, fmt.Errorf("perf event enable: %v", err)
	}

	if err := unix.IoctlSetInt(efd, unix.PERF_EVENT_IOC_SET_BPF, fd); err != nil {
		unix.Close(efd)
		return nil, fmt.Errorf("perf event set bpf: %v", err)
	}

	return func() { unix.Close(efd) }, nil
}

func pmuType() (uint32, error) {
	const PMUTypeFile = "/sys/bus/event_source/devices/kprobe/type"

	data, err := ioutil.ReadFile(PMUTypeFile)
	if err != nil {
		return 0, err
	}
	tid := strings.TrimSuffix(string(data), "\n")
	tidU64, err := strconv.ParseUint(tid, 10, 64)
	if err != nil {
		return 0, err
	}

	return uint32(tidU64), nil
}

// https://github.com/cilium/ebpf/blob/master/internal/ptr.go#L20
func newStringPointer(str string) uintptr {
	if str == "" {
		return 0
	}

	// The kernel expects strings to be zero terminated
	buf := make([]byte, len(str)+1)
	copy(buf, str)

	return uintptr(unsafe.Pointer(&buf[0]))
}
