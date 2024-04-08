//go:build linux

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -tags "linux" bpf tcptoa_sockops.c -- -I../headers

package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	"golang.org/x/sys/unix"
)

func findCgroupPath() (string, error) {

	cgroupPath := "/sys/fs/cgroup"

	var st syscall.Statfs_t
	if err := syscall.Statfs(cgroupPath, &st); err != nil {
		return "", fmt.Errorf("failed to stat %s: %w", cgroupPath, err)
	}

	isCgoupV2Enabled := st.Type == unix.CGROUP2_SUPER_MAGIC
	if !isCgoupV2Enabled {
		cgroupPath = filepath.Join(cgroupPath, "unified")
	}

	return cgroupPath, nil
}

func main() {

	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to remove memory limit: %v", err)
	}

	cgroupPath, err := findCgroupPath()
	if err != nil {
		log.Fatalf("failed to find cgroup path: %v", err)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("failed to load BPF objects: %v", err)
	}

	defer objs.Close()

	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: objs.bpfPrograms.BpfSockopsCb,
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		log.Fatalf("failed to attach cgroup: %v", err)
	}

	defer link.Close()

	<-stopper
}
