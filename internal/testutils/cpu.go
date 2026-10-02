package testutils

import (
	"runtime"
	"testing"

	"github.com/cilium/ebpf/internal/unix"

	"github.com/go-quicktest/qt"
)

// LockOSThreadToSingleCPU force the current goroutine to run on a single CPU.
func LockOSThreadToSingleCPU(tb testing.TB) {
	LockOSThreadToSingleCPUID(tb, 0)
}

// LockOSThreadToSingleCPUInt force the current goroutine to run on a single CPU specified by cpuID.
// Skips the test if the requested CPU is not available.
func LockOSThreadToSingleCPUID(tb testing.TB, cpuID int) {
	tb.Helper()

	runtime.LockOSThread()
	tb.Cleanup(runtime.UnlockOSThread)

	var old unix.CPUSet
	err := unix.SchedGetaffinity(0, &old)
	qt.Assert(tb, qt.IsNil(err))

	// Check if the requested CPU is available
	if !old.IsSet(cpuID) {
		runtime.UnlockOSThread()
		tb.Skipf("CPU %d is not available", cpuID)
	}

	var cpuSet unix.CPUSet
	cpuSet.Set(cpuID)
	err = unix.SchedSetaffinity(0, &cpuSet)
	qt.Assert(tb, qt.IsNil(err))

	tb.Cleanup(func() {
		_ = unix.SchedSetaffinity(0, &old)
	})
}
