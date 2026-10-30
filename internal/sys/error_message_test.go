package sys

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf/internal/unix"
	"testing"
)

type customError []int

func (customError) Error() string { return "custom" }
func TestErrnoMessage(t *testing.T) {
	for _, errno := range []unix.Errno{0, unix.EPERM, unix.E2BIG, ENOTSUPP, unix.Errno(^uintptr(0))} {
		for _, err := range []error{errno, wrappedErrno{errno}} {
			msg, ok := ErrnoMessage(err)
			if !ok || msg != err.Error() {
				t.Fatalf("bad message %q", msg)
			}
			for _, prefix := range []string{"masking profiler signal: ", "unmasking profiler signal: "} {
				got := profilerSignalError(prefix, err)
				want := fmt.Errorf(prefix+"%w", err)
				if got.Error() != want.Error() || errors.Unwrap(got) != err || !errors.Is(got, errno) {
					t.Fatal("profiler error changed")
				}
			}
		}
	}
	for _, err := range []error{nil, customError{1}, Error(customError{}, unix.EPERM)} {
		if _, ok := ErrnoMessage(err); ok {
			t.Fatal("foreign error recognized")
		}
		got := profilerSignalError("masking profiler signal: ", err)
		want := fmt.Errorf("masking profiler signal: %w", err)
		if got.Error() != want.Error() {
			t.Fatal("fallback changed")
		}
	}
}

type signalFormatter struct{ calls int }

func (e *signalFormatter) Error() string { panic("unexpected Error") }
func (e *signalFormatter) Format(s fmt.State, verb rune) {
	e.calls++
	fmt.Fprint(s, "formatted signal")
}

type signalMutable struct {
	text  string
	calls int
}

func (e *signalMutable) Error() string { e.calls++; return e.text }

type signalPanic struct{}

func (*signalPanic) Error() string { panic("bad signal") }
func TestProfilerSignalErrorForeign(t *testing.T) {
	for _, cause := range []error{&signalPanic{}, (*signalPanic)(nil), customError{1}, nil} {
		got := profilerSignalError("masking profiler signal: ", cause)
		want := fmt.Errorf("masking profiler signal: %w", cause)
		if got.Error() != want.Error() {
			t.Fatal("foreign semantics changed")
		}
	}
	f := new(signalFormatter)
	got := profilerSignalError("unmasking profiler signal: ", f)
	if f.calls != 1 || got.Error() != "unmasking profiler signal: formatted signal" || got.Error() != "unmasking profiler signal: formatted signal" || f.calls != 1 {
		t.Fatal("Formatter semantics changed")
	}
	e := &signalMutable{text: "before"}
	got = profilerSignalError("masking profiler signal: ", e)
	e.text = "after"
	if got.Error() != "masking profiler signal: before" || got.Error() != "masking profiler signal: before" || e.calls != 1 {
		t.Fatal("snapshot changed")
	}
}

func TestErrnoMessageRange(t *testing.T) {
	// Cover known platform messages and unknown values without invoking syscalls.
	for errno := unix.Errno(0); errno < 4096; errno++ {
		for _, cause := range []error{errno, wrappedErrno{errno}} {
			message, ok := ErrnoMessage(cause)
			if !ok || message != fmt.Sprint(cause) {
				t.Fatalf("errno %d differs", errno)
			}
		}
	}
}

var signalErrorSink error

func TestSignalErrorAllocations(t *testing.T) {
	t.Logf("allocations/run = %g (measurement only)", testing.AllocsPerRun(100, func() { signalErrorSink = profilerSignalError("masking profiler signal: ", unix.EPERM) }))
	signalErrorSink = nil
}
