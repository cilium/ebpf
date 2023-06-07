package sys

import (
	"fmt"
	"runtime"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"

	qt "github.com/frankban/quicktest"
)

func TestSigset(t *testing.T) {
	const maxSignal = unix.Signal(unsafe.Sizeof(unix.Sigset_t{}) * 8)

	// Type-infer a sigset word. This is a typed uint of 32 or 64 bits depending
	// on the target architecture, so we can't use an untyped uint.
	zero := unix.Sigset_t{}.Val[0]
	words := len(unix.Sigset_t{}.Val)

	var want, got unix.Sigset_t
	// Flip the first bit of the first word.
	if err := sigsetAdd(&got, 1); err != nil {
		t.Fatal(err)
	}
	want.Val[0] = 1
	if want != got {
		t.Fatalf("expected first word to be 0x%x, got: 0x%x", want, got)
	}

	// And the last bit of the last word.
	if err := sigsetAdd(&got, maxSignal); err != nil {
		t.Fatal(err)
	}
	want.Val[words-1] = ^(^zero >> 1)
	if want != got {
		t.Fatalf("expected last word to be 0x%x, got: 0x%x", want, got)
	}

	if err := sigsetAdd(&got, maxSignal+1); err == nil {
		t.Fatal("expected out-of-bounds add to be rejected")
	}
	if err := sigsetAdd(&got, -1); err == nil {
		t.Fatal("expected negative signal to be rejected")
	}
}

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
	qt.Assert(t, sigsetAdd(&want, unix.SIGPROF), qt.IsNil)
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
func sigsetAdd(set *unix.Sigset_t, signal unix.Signal) error {
	if signal < 1 {
		return fmt.Errorf("signal %d must be larger than 0", signal)
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
		return fmt.Errorf("signal %d does not fit within unix.Sigset_t", signal)
	}

	// Write the signal bit into its corresponding word at the corrected offset.
	set.Val[word] |= 1 << (bit % wordBits)

	return nil
}
