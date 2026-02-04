package testutils

import (
	"runtime"
	"testing"

	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/unix"
)

type Capability int

// Mirrors of constants from x/sys/unix
const (
	CAP_NET_ADMIN    Capability = 12
	CAP_SYS_ADMIN    Capability = 21
	CAP_SYS_RESOURCE Capability = 24
	CAP_PERFMON      Capability = 38
	CAP_BPF          Capability = 39
)

// WithCapabilities runs `f` with only the given capabilities
// in the effective set. This allows us to assert that certain operations
// only require specific capabilities.
//
// The code in `f` and any code called by `f` must NOT call [runtime.LockOSThread],
// as this could leave the current goroutine permanently pinned to an OS thread.
// It must also not create any goroutines of its own, as that will result in a new
// OS thread being created that may or may not inherit the new capabilities of its
// parent, and will later be released into the schedulable pool of threads available
// for goroutine scheduling.
//
// Warning: on non-linux platforms, this function calls through to `f` without
// side effects.
func WithCapabilities(tb testing.TB, caps []Capability, f func()) {
	tb.Helper()

	if !platform.IsLinux {
		f()
		return
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	orig, err := capget()
	if err != nil {
		tb.Fatal("Can't get capabilities:", err)
	}

	var set capUserData
	for _, cap := range caps {
		set.Effective |= 1 << uint(cap)
	}
	set.Permitted = orig.Permitted

	if err := capset(set); err != nil {
		tb.Fatal("Can't set capabilities:", err)
	}

	f()

	if err := capset(orig); err != nil {
		tb.Fatal("Can't restore capabilities:", err)
	}
}

type capUserData struct {
	Effective   uint64
	Permitted   uint64
	Inheritable uint64
}

func capget() (capUserData, error) {
	var hdr = &unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
	}

	var data [2]unix.CapUserData
	err := unix.Capget(hdr, &data[0])
	if err != nil {
		return capUserData{}, err
	}

	return capUserData{
		Effective:   uint64(data[0].Effective) | uint64(data[1].Effective)<<32,
		Permitted:   uint64(data[0].Permitted) | uint64(data[1].Permitted)<<32,
		Inheritable: uint64(data[0].Inheritable) | uint64(data[1].Inheritable)<<32,
	}, err
}

func capset(data capUserData) error {
	var hdr = &unix.CapUserHeader{
		Version: unix.LINUX_CAPABILITY_VERSION_3,
	}

	var linuxData [2]unix.CapUserData
	linuxData[0].Effective = uint32(data.Effective & 0xFFFFFFFF)
	linuxData[0].Permitted = uint32(data.Permitted & 0xFFFFFFFF)
	linuxData[0].Inheritable = uint32(data.Inheritable & 0xFFFFFFFF)
	linuxData[1].Effective = uint32(data.Effective >> 32)
	linuxData[1].Permitted = uint32(data.Permitted >> 32)
	linuxData[1].Inheritable = uint32(data.Inheritable >> 32)

	return unix.Capset(hdr, &linuxData[0])
}
