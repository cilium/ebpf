package sys

import (
	"runtime"
	"testing"

	"github.com/cilium/ebpf/internal/unix"
	qt "github.com/frankban/quicktest"
)

func TestProfilerSignal(t *testing.T) {
	// Additional goroutine lock to make the PthreadSigmask below execute on the
	// same OS thread as the functions under test. UnlockOSThread needs to be
	// called as many times as LockOSThread to unlock the goroutine.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var old unix.Sigset_t
	if err := unix.PthreadSigmask(0, nil, &old); err != nil {
		t.Fatal("getting old sigmask:", err)
	}

	maskProfilerSignal()

	var have unix.Sigset_t
	if err := unix.PthreadSigmask(0, nil, &have); err != nil {
		t.Fatal("getting old sigmask:", err)
	}

	want := have
	sigsetAdd(t, &want, unix.SIGPROF)
	qt.Assert(t, have, qt.Equals, want)

	unmaskProfilerSignal()

	if err := unix.PthreadSigmask(0, nil, &have); err != nil {
		t.Fatal("getting old sigmask:", err)
	}

	qt.Assert(t, have, qt.Equals, old)
}

// sigsetAdd adds signal to set.
//
// Note: Sigset_t.Val's value type is uint32 or uint64 depending on the arch.
// This function must be able to deal with both and so must avoid any direct
// references to u32 or u64 types.
func sigsetAdd(tb testing.TB, set *unix.Sigset_t, signal unix.Signal) {
	if signal < 1 {
		tb.Fatalf("signal %d must be larger than 0", signal)
	}

	// For amd64, runtime.sigaddset() performs the following operation:
	// set[(signal-1)/32] |= 1 << ((uint32(signal) - 1) & 31)
	//
	// This trick depends on sigset being two u32's, causing a signal in the the
	// bottom 31 bits to be written to the low word if bit 32 is low, or the high
	// word if bit 32 is high.

	// Signal is the nth bit in the bitfield.
	bit := int(signal - 1)
	// Word within the sigset the bit needs to be written to.
	word := bit / wordBits

	if word >= len(set.Val) {
		tb.Fatalf("signal %d does not fit within unix.Sigset_t", signal)
	}

	// Write the signal bit into its corresponding word at the corrected offset.
	set.Val[word] |= 1 << (bit % wordBits)
}
