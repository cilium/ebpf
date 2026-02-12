//go:build linux

// This program tests BPF token support by creating a token and exercising
// feature probes, program loading, and map creation with it.
//
// Usage:
//
//	token-test [--drop-caps] [/path/to/bpffs]
//
// With --drop-caps, the program creates the token first, then drops
// CAP_BPF, CAP_SYS_ADMIN, and CAP_PERFMON before running probes.
// This proves the token is the sole source of BPF access.
//
// If no path is given, defaults to /sys/fs/bpf.
package main

import (
	"fmt"
	"log"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"

	"golang.org/x/sys/unix"
)

const bpfTokenCreate = 36 // BPF_TOKEN_CREATE command number

// tokenCreateAttr mirrors the kernel's bpf_attr for BPF_TOKEN_CREATE.
type tokenCreateAttr struct {
	flags   uint32
	bpffsFd uint32
}

func createBPFToken(bpffsPath string) (int, error) {
	bpffsFd, err := unix.Open(bpffsPath, unix.O_DIRECTORY, 0)
	if err != nil {
		return -1, fmt.Errorf("open bpffs %s: %w", bpffsPath, err)
	}
	defer unix.Close(bpffsFd)

	attr := tokenCreateAttr{bpffsFd: uint32(bpffsFd)}
	fd, _, errno := unix.Syscall(
		unix.SYS_BPF,
		uintptr(bpfTokenCreate),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return -1, fmt.Errorf("BPF_TOKEN_CREATE: %w", errno)
	}
	return int(fd), nil
}

func dropBPFCaps() error {
	// Capabilities to drop: CAP_SYS_ADMIN=21, CAP_PERFMON=38, CAP_BPF=39
	caps := []uintptr{21, 38, 39}
	for _, cap := range caps {
		// PR_CAPBSET_DROP = 24
		_, _, errno := unix.Syscall(unix.SYS_PRCTL, 24, cap, 0)
		if errno != 0 {
			return fmt.Errorf("PR_CAPBSET_DROP cap %d: %w", cap, errno)
		}
	}

	// Also clear the caps from the effective/permitted sets via capset.
	// We need to read current caps, clear the BPF-related ones, then write back.
	var hdr [2]uint64 // version + pid
	var data [2][3]uint64 // effective, permitted, inheritable (x2 for 64-bit)

	// Use _LINUX_CAPABILITY_VERSION_3 = 0x20080522
	hdr[0] = 0x20080522
	hdr[1] = 0 // current process

	_, _, errno := unix.Syscall(unix.SYS_CAPGET, uintptr(unsafe.Pointer(&hdr[0])), uintptr(unsafe.Pointer(&data[0])), 0)
	if errno != 0 {
		return fmt.Errorf("capget: %w", errno)
	}

	// Clear CAP_SYS_ADMIN (21), CAP_PERFMON (38), CAP_BPF (39)
	// Caps 0-31 are in data[0], caps 32-63 are in data[1]
	data[0][0] &^= (1 << 21) // effective: clear CAP_SYS_ADMIN
	data[0][1] &^= (1 << 21) // permitted: clear CAP_SYS_ADMIN

	data[1][0] &^= (1 << (38 - 32)) // effective: clear CAP_PERFMON
	data[1][0] &^= (1 << (39 - 32)) // effective: clear CAP_BPF
	data[1][1] &^= (1 << (38 - 32)) // permitted: clear CAP_PERFMON
	data[1][1] &^= (1 << (39 - 32)) // permitted: clear CAP_BPF

	_, _, errno = unix.Syscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr[0])), uintptr(unsafe.Pointer(&data[0])), 0)
	if errno != 0 {
		return fmt.Errorf("capset: %w", errno)
	}

	return nil
}

func runProbes(tokenFD int) {
	fmt.Println("\n=== Feature Probes (with token) ===")
	features.SetGlobalToken(tokenFD)

	progTypes := []ebpf.ProgramType{
		ebpf.SocketFilter,
		ebpf.Kprobe,
		ebpf.SchedCLS,
		ebpf.XDP,
		ebpf.TracePoint,
		ebpf.CGroupSKB,
	}
	for _, pt := range progTypes {
		err := features.HaveProgramType(pt)
		status := "supported"
		if err != nil {
			status = err.Error()
		}
		fmt.Printf("  prog %-20s %s\n", pt, status)
	}

	mapTypes := []ebpf.MapType{
		ebpf.Hash,
		ebpf.Array,
		ebpf.PerfEventArray,
		ebpf.LRUHash,
		ebpf.RingBuf,
	}
	for _, mt := range mapTypes {
		err := features.HaveMapType(mt)
		status := "supported"
		if err != nil {
			status = err.Error()
		}
		fmt.Printf("  map  %-20s %s\n", mt, status)
	}

	// Load a trivial program with token
	fmt.Println("\n=== Program Load (with token) ===")
	prog, err := ebpf.NewProgramWithOptions(&ebpf.ProgramSpec{
		Name: "token_test",
		Type: ebpf.SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	}, ebpf.ProgramOptions{
		TokenFD: tokenFD,
	})
	if err != nil {
		fmt.Printf("  program load: FAILED (%v)\n", err)
	} else {
		fmt.Printf("  program load: OK (fd=%d)\n", prog.FD())
		prog.Close()
	}

	// Create a map with token
	fmt.Println("\n=== Map Create (with token) ===")
	m, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Name:       "token_test",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}, ebpf.MapOptions{
		TokenFD: tokenFD,
	})
	if err != nil {
		fmt.Printf("  map create: FAILED (%v)\n", err)
	} else {
		fmt.Printf("  map create: OK (fd=%d)\n", m.FD())
		m.Close()
	}

	// Clear token and verify probes fail without it.
	// Use a program type NOT tested above to avoid cached results.
	fmt.Println("\n=== Without Token (uncached probe) ===")
	features.SetGlobalToken(-1)
	err = features.HaveProgramType(ebpf.PerfEvent)
	status := "supported"
	if err != nil {
		status = err.Error()
	}
	fmt.Printf("  prog PerfEvent (no token):     %s\n", status)

	err = features.HaveMapType(ebpf.PerCPUHash)
	status = "supported"
	if err != nil {
		status = err.Error()
	}
	fmt.Printf("  map  PerCPUHash (no token):     %s\n", status)
	if err == nil {
		val, rerr := os.ReadFile("/proc/sys/kernel/unprivileged_bpf_disabled")
		if rerr == nil {
			fmt.Printf("  NOTE: kernel.unprivileged_bpf_disabled = %s", val)
			fmt.Println("        Map creation succeeded without token because unprivileged BPF is enabled.")
		}
	}
}

func main() {
	dropCaps := false
	bpffsPath := "/sys/fs/bpf"

	for _, arg := range os.Args[1:] {
		if arg == "--drop-caps" {
			dropCaps = true
		} else {
			bpffsPath = arg
		}
	}

	// Step 1: Create BPF token (needs CAP_BPF)
	fmt.Printf("Creating BPF token from %s...\n", bpffsPath)
	tokenFD, err := createBPFToken(bpffsPath)
	if err != nil {
		log.Fatalf("Failed to create BPF token: %v", err)
	}
	defer unix.Close(tokenFD)
	fmt.Printf("BPF token created: fd=%d\n", tokenFD)

	// Step 2: Optionally drop BPF capabilities
	if dropCaps {
		fmt.Println("\nDropping CAP_BPF, CAP_SYS_ADMIN, CAP_PERFMON...")
		if err := dropBPFCaps(); err != nil {
			log.Fatalf("Failed to drop capabilities: %v", err)
		}
		fmt.Println("Capabilities dropped. BPF access now depends solely on token.")
	}

	// Step 3: Run all probes
	runProbes(tokenFD)

	fmt.Println("\nDone.")
}
