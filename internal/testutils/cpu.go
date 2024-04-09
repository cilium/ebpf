package testutils

import (
	"runtime"
	"testing"

	"github.com/cilium/ebpf/internal/unix"

	"github.com/go-quicktest/qt"
)

// LockOSThreadToSingleCPU force the current goroutine to run on a single CPU.
func LockOSThreadToSingleCPU(tb testing.TB) {
	tb.Helper()

	runtime.LockOSThread()
	tb.Cleanup(runtime.UnlockOSThread)

	var old unix.CPUSet
	err := unix.SchedGetaffinity(0, &old)
	qt.Assert(tb, qt.IsNil(err))

	// Schedule test to run on only CPU 0
	var first unix.CPUSet
	first.Set(0)
	err = unix.SchedSetaffinity(0, &first)
	qt.Assert(tb, qt.IsNil(err))

	tb.Cleanup(func() {
		_ = unix.SchedSetaffinity(0, &old)
	})
}
