//go:build linux
// +build linux

// This program demonstrates attaching a fentry eBPF program to
// tcp_close and reading the RTT from the TCP socket using CO-RE helpers.
// It prints the IPs/ports/RTT information
// once the host closes a TCP connection.
// It supports only IPv4 for this example.
//
// Sample output:
//
// examples# go run -exec sudo ./tcprtt
// 2022/03/19 22:30:34 Src addr        Port   -> Dest addr       Port   RTT
// 2022/03/19 22:30:36 10.0.1.205      50578  -> 117.102.109.186 5201   195
// 2022/03/19 22:30:53 10.0.1.205      0      -> 89.84.1.178     9200   30
// 2022/03/19 22:30:53 10.0.1.205      36022  -> 89.84.1.178     9200   28

package main

import (
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"github.com/containers/common/pkg/cgroupv2"
)

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf tcprtt_sockops.c -- -I../headers

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

	cgroupPath, err := getCgroupPath()
	if err != nil {
		log.Fatal(err)
	}

	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.bpfPrograms.BpfSockopsCb,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		log.Fatal(err)
	}
	defer link.Close()

	log.Printf("eBPF program loaded and attached on cgroup %s\n", cgroupPath)

	// Wait
	<-stopper
}

func getCgroupPath() (string, error) {
	var err error = nil
	cgroupPath := "/sys/fs/cgroup"

	enabled, err := cgroupv2.Enabled()
	if !enabled {
		cgroupPath = filepath.Join(cgroupPath, "unified")
	}
	return cgroupPath, err
}
