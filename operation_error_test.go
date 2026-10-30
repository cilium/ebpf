package ebpf

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

type changingError struct {
	text  string
	calls int
}

func (e *changingError) Error() string { e.calls++; return e.text }

type formatterError struct{}

func (formatterError) Error() string              { panic("Error must not be called") }
func (formatterError) Format(s fmt.State, v rune) { fmt.Fprint(s, "formatted") }

type panicError struct{}

func (panicError) Error() string { panic("bad error") }

type sliceError []int

func (sliceError) Error() string { return "slice" }

type nilError struct{}

func (*nilError) Error() string { panic("nil") }

func checkOperationError(t *testing.T, got, want, cause error) {
	t.Helper()
	if got.Error() != want.Error() {
		t.Fatalf("message %q != %q", got, want)
	}
	if !reflect.DeepEqual(errors.Unwrap(got), cause) {
		t.Fatalf("changed immediate cause: %#v", errors.Unwrap(got))
	}
	first := got.Error()
	if got.Error() != first {
		t.Fatal("unstable Error")
	}
	for a, b := got, want; ; a, b = errors.Unwrap(a), errors.Unwrap(b) {
		if (a == nil) != (b == nil) {
			t.Fatal("chain depth changed")
		}
		if a == nil {
			break
		}
	}
}

func TestOperationErrorCompatibility(t *testing.T) {
	causes := []error{unix.Errno(0), unix.EPERM, unix.E2BIG, unix.Errno(^uintptr(0)), sysErrKeyNotExist, sysErrKeyExist, sysErrNotSupported, formatterError{}, panicError{}, sliceError{1}, (*nilError)(nil), nil}
	for _, cause := range causes {
		for _, prefix := range []string{"lookup: ", "update: ", "key too big for map: ", "run program: "} {
			got := wrapOperationError(prefix, cause)
			want := fmt.Errorf(prefix+"%w", cause)
			checkOperationError(t, got, want, cause)
			var ge, we unix.Errno
			if errors.As(got, &ge) != errors.As(want, &we) || ge != we {
				t.Fatal("As differs")
			}
			for _, target := range []error{unix.EPERM, unix.E2BIG, ErrKeyNotExist, ErrNotSupported} {
				if errors.Is(got, target) != errors.Is(want, target) {
					t.Fatal("Is differs")
				}
			}
		}
	}
	e := &changingError{text: "before"}
	got := wrapOperationError("lookup: ", e)
	if e.calls != 1 {
		t.Fatalf("calls=%d", e.calls)
	}
	e.text = "after"
	if got.Error() != "lookup: before" || got.Error() != "lookup: before" || e.calls != 1 {
		t.Fatal("not an eager snapshot")
	}
	inner := wrapOperationError("key too big for map: ", unix.E2BIG)
	checkOperationError(t, wrapOperationError("update: ", inner), fmt.Errorf("update: %w", inner), inner)
	if _, ok := wrapOperationError("lookup: ", sys.Error(formatterError{}, unix.EPERM)).(*operationError); ok {
		t.Fatal("arbitrary syscallError optimized")
	}
}

func TestUnsupportedRunError(t *testing.T) {
	original := ErrNotSupported
	t.Cleanup(func() { ErrNotSupported = original })
	for _, cause := range []error{original, formatterError{}, panicError{}, sliceError{1}, (*nilError)(nil), nil} {
		ErrNotSupported = cause
		for _, typ := range []ProgramType{SocketFilter, ProgramType(33), ProgramType(^uint32(0))} {
			got := unsupportedRunError(typ)
			want := fmt.Errorf("kernel doesn't support running %s: %w", typ, cause)
			checkOperationError(t, got, want, cause)
		}
	}
}

// Construction must not inspect foreign error chains or call Error twice.
type observedError struct{ calls [4]int }

func (e *observedError) Error() string { e.calls[0]++; return "observed" }
func (e *observedError) Is(error) bool { e.calls[1]++; return false }
func (e *observedError) As(any) bool   { e.calls[2]++; return false }
func (e *observedError) Unwrap() error { e.calls[3]++; return unix.EPERM }

func TestOperationErrorForeignCallbacks(t *testing.T) {
	e := new(observedError)
	got := wrapOperationError("run program: ", e)
	if e.calls != [4]int{1, 0, 0, 0} {
		t.Fatalf("unexpected callbacks: %v", e.calls)
	}
	for i := 0; i < 3; i++ {
		if got.Error() != "run program: observed" {
			t.Fatal("message changed")
		}
	}
	if e.calls != [4]int{1, 0, 0, 0} {
		t.Fatal("Error repeated callbacks")
	}
	original := ErrNotSupported
	t.Cleanup(func() { ErrNotSupported = original })
	e2 := &changingError{text: "first"}
	ErrNotSupported = e2
	got = unsupportedRunError(ProgramType(^uint32(0)))
	e2.text = "second"
	if got.Error() != "kernel doesn't support running ProgramType(4294967295): first" || e2.calls != 1 {
		t.Fatal("unsupported error not snapshotted")
	}
}

func TestMapErrorChains(t *testing.T) {
	for _, cause := range []error{unix.ENOENT, unix.EEXIST, sys.ENOTSUPP, unix.E2BIG, unix.EPERM} {
		mapped := wrapMapError(cause)
		var want error
		switch cause {
		case unix.ENOENT:
			want = sysErrKeyNotExist
		case unix.EEXIST:
			want = sysErrKeyExist
		case sys.ENOTSUPP:
			want = sysErrNotSupported
		case unix.E2BIG:
			want = fmt.Errorf("key too big for map: %w", cause)
		default:
			want = cause
		}
		if mapped.Error() != want.Error() {
			t.Fatal("mapping message changed")
		}
		got := wrapOperationError("update: ", mapped)
		legacy := fmt.Errorf("update: %w", want)
		checkOperationError(t, got, legacy, mapped)
		if !errors.Is(got, cause) {
			t.Fatal("lost errno")
		}
		if cause == unix.E2BIG {
			if errors.Unwrap(errors.Unwrap(got)) != cause {
				t.Fatal("E2BIG cause flattened")
			}
		}
	}
	if wrapMapError(unix.ENOENT) != sysErrKeyNotExist {
		t.Fatal("lost singleton")
	}
}

var operationErrorSink error

func TestClosedErrorAllocations(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func() error
	}{
		{"ordinary", func() error { return wrapOperationError("update: ", unix.EPERM) }},
		{"e2big", func() error { return wrapOperationError("update: ", wrapMapError(unix.E2BIG)) }},
		{"unsupported", func() error { return wrapOperationError("run program: ", unsupportedRunError(ProgramType(^uint32(0)))) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("allocations/run = %g (measurement, not a total worker bound)", testing.AllocsPerRun(100, func() { operationErrorSink = tc.make() }))
			operationErrorSink = nil
		})
	}
}
