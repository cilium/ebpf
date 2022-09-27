package sys

import (
	"fmt"
	"runtime"

	"github.com/cilium/ebpf/internal/unix"
)

var profSet unix.Sigset_t

func init() {
	if err := unix.SigsetAdd(&profSet, unix.SIGPROF); err != nil {
		panic(fmt.Errorf("creating signal set: %w", err))
	}
}

// MaskProfilerSignal locks the calling goroutine to its underlying OS thread
// and adds SIGPROF to the thread's signal mask. This prevents pprof from
// interrupting expensive syscalls like e.g. BPF_PROG_LOAD.
//
// Call defer sys.UnmaskProfilerSignal() to reverse the operation.
func MaskProfilerSignal() {
	runtime.LockOSThread()

	if err := unix.PthreadSigmask(unix.SIG_BLOCK, &profSet, nil); err != nil {
		panic(fmt.Errorf("masking profiler signal: %w", err))
	}
}

// UnmaskProfilerSignal removes SIGPROF from the underlying thread's signal
// mask, allowing it to be interrupted for profiling once again.
//
// It also unlocks the current goroutine from its underlying OS thread.
func UnmaskProfilerSignal() {
	defer runtime.UnlockOSThread()

	if err := unix.PthreadSigmask(unix.SIG_UNBLOCK, &profSet, nil); err != nil {
		panic(fmt.Errorf("unmasking profiler signal: %w", err))
	}
}
