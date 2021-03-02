package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "$BPF_CFLAGS" -cc clang-10 KProbeExample ./bpf/kprobe_example.c

const Key uint32 = 0

// This program demonstrates how to attach an eBPF program to a kprobe.
// The program will be attached to the __x64_sys_execve syscall and print out
// the number of times it has been called every second.
func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	var originalLimit unix.Rlimit
	// Get the original rlimit values so we can restore them laster.
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &originalLimit); err != nil {
		panic(fmt.Errorf("failed to get rlimit: %v", err))
	}
	// Increase rlimit so the eBPF map and program can be loaded.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		panic(fmt.Errorf("failed to set temporary rlimit: %v", err))
	}
	defer func() {
		// Restore original rlimit values.
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &originalLimit); err != nil {
			panic(fmt.Errorf("failed to restore original rlimit: %v", err))
		}
	}()

	// Load Program and Map
	specs, err := NewKProbeExampleSpecs()
	if err != nil {
		panic(fmt.Errorf("error while loading specs: %v", err))
	}
	objs, err := specs.Load(nil)
	if err != nil {
		panic(fmt.Errorf("error while loading objects: %v", err))
	}

	// Create and attach __x64_sys_execve kprobe
	kp, err := New("__x64_sys_execve")
	if err != nil {
		panic(fmt.Errorf("error while creating kprobe: %v", err))
	}
	closer, err := kp.Attach(uint32(objs.ProgramKprobeExampleProg.FD()))
	if err != nil {
		panic(fmt.Errorf("error while attaching kprobe: %v", err))
	}
	defer func() {
		fmt.Printf("detaching and removing kprobe %s\n", kp.Descriptor())
		if err := kp.Close(); err != nil {
			panic(fmt.Errorf("error while detaching kprobe %s: %v", kp.Descriptor(), err))
		}
	}()
	defer closer()

	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			var value uint64
			if err := objs.MapKprobeExampleMap.Lookup(Key, &value); err != nil {
				if errors.Is(err, ebpf.ErrKeyNotExist) {
					fmt.Println("__x64_sys_execve not yet called")
					continue
				}
				panic(fmt.Errorf("error while reading map: %v", err))
			}
			fmt.Printf("__x64_sys_execve called %d times\n", value)
		case <-stopper:
			return
		}
	}
}
