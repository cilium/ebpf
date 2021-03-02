// This program demonstrates how to attach an eBPF program to a kprobe.
// The program will be attached to the __x64_sys_execve syscall and print out
// the number of times it has been called every second.

package main

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	goperf "github.com/elastic/go-perf"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-11 KProbeExample ./bpf/kprobe_example.c

const (
	mapKey           uint32 = 0
	kProbesPath      string = "/sys/kernel/debug/tracing/events/kprobes/"
	kProbeEventsPath string = "/sys/kernel/debug/tracing/kprobe_events"
)

func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Increase rlimit so the eBPF map and program can be loaded.
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		panic(fmt.Errorf("failed to set temporary rlimit: %v", err))
	}

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
	closer, err := createAndAttachKProbe("__x64_sys_execve", uint32(objs.ProgramKprobeExecve.FD()))
	if err != nil {
		panic(fmt.Errorf("create and attach KProbe: %v", err))
	}
	defer closer()

	ticker := time.NewTicker(1 * time.Second)
	for {
		select {
		case <-ticker.C:
			var value uint64
			if err := objs.MapKprobeMap.Lookup(mapKey, &value); err != nil {
				panic(fmt.Errorf("error while reading map: %v", err))
			}
			fmt.Printf("__x64_sys_execve called %d times\n", value)
		case <-stopper:
			return
		}
	}
}

// This function register a new kprobe in `kProbeEventsPath`
func createAndAttachKProbe(syscall string, fd uint32) (func(), error) {
	identifier := fmt.Sprintf("%s_%s", genID(), syscall)

	if err := appendToFile(kProbeEventsPath, fmt.Sprintf("p:kprobes/%s %s", identifier, syscall)); err != nil {
		return nil, fmt.Errorf("error while creating kprobe: %v", err)
	}

	closer, err := attachKProbe(identifier, fd)
	if err != nil {
		return nil, fmt.Errorf("error while attaching kprobe: %v", err)
	}

	return closer, nil
}

type configuratorFunc func(attr *goperf.Attr) error

// Implements goperf.Configurator
func (cf configuratorFunc) Configure(attr *goperf.Attr) error { return cf(attr) }

func attachKProbe(identifier string, fd uint32) (func(), error) {
	var (
		closer                           = func() {}
		attr                             = &goperf.Attr{}
		configurator goperf.Configurator = configuratorFunc(func(attr *goperf.Attr) error {
			kpID, err := getKProbeID(identifier)
			if err != nil {
				return err
			}
			attr.Label = identifier
			attr.Type = goperf.TracepointEvent
			attr.Config = kpID
			return nil
		})
	)

	if err := configurator.Configure(attr); err != nil {
		return closer, err
	}

	runtime.LockOSThread()
	closer = func() { runtime.UnlockOSThread() }

	perfEv, err := goperf.Open(attr, goperf.CallingThread, goperf.AnyCPU, nil)
	if err != nil {
		return closer, err
	}
	closer = func() {
		perfEv.Close()
		runtime.UnlockOSThread()
	}

	if err := perfEv.Enable(); err != nil {
		return closer, err
	}

	err = perfEv.SetBPF(fd)
	return func() {
		if err := perfEv.Disable(); err != nil {
			panic(err)
		}
		perfEv.Close()
		if err := removeKProbe(identifier); err != nil {
			panic(err)
		}
	}, err
}

func getKProbeID(identifier string) (uint64, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("%s%s/id", kProbesPath, identifier))
	if err != nil {
		return 0, err
	}
	tid := strings.TrimSuffix(string(data), "\n")
	return strconv.ParseUint(tid, 10, 64)
}

func removeKProbe(identifier string) error {
	return appendToFile(kProbeEventsPath, fmt.Sprintf("-:kprobes/%s", identifier))
}

func appendToFile(path string, content string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.WriteString(content); err != nil {
		return err
	}
	return nil
}

// Generate a random string
func genID() string {
	var (
		size  = 10
		chars = []rune("abcdefghijklmnopqrstuvwxyz")
	)

	s := make([]rune, size)
	for i := range s {
		s[i] = chars[rand.Intn(len(chars))]
	}

	return string(s)
}
