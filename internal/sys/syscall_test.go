package sys

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/internal/unix"

	qt "github.com/frankban/quicktest"
)

func TestObjName(t *testing.T) {
	name := NewObjName("more_than_16_characters_long")
	if name[len(name)-1] != 0 {
		t.Error("NewBPFObjName doesn't null terminate")
	}
	if len(name) != unix.BPF_OBJ_NAME_LEN {
		t.Errorf("Name is %d instead of %d bytes long", len(name), unix.BPF_OBJ_NAME_LEN)
	}
}

func TestWrappedErrno(t *testing.T) {
	a := error(wrappedErrno{unix.EINVAL})
	b := error(unix.EINVAL)

	if a == b {
		t.Error("wrappedErrno is comparable to plain errno")
	}

	if !errors.Is(a, b) {
		t.Error("errors.Is(wrappedErrno, errno) returns false")
	}

	if errors.Is(a, unix.EAGAIN) {
		t.Error("errors.Is(wrappedErrno, EAGAIN) returns true")
	}

	notsupp := wrappedErrno{ENOTSUPP}
	qt.Assert(t, notsupp.Error(), qt.Contains, "operation not supported")
}

func TestSyscallError(t *testing.T) {
	err := errors.New("foo")
	foo := Error(err, unix.EINVAL)

	if !errors.Is(foo, unix.EINVAL) {
		t.Error("SyscallError is not the wrapped errno")
	}

	if !errors.Is(foo, err) {
		t.Error("SyscallError is not the wrapped error")
	}

	if errors.Is(unix.EINVAL, foo) {
		t.Error("Errno is the SyscallError")
	}

	if errors.Is(err, foo) {
		t.Error("Error is the SyscallError")
	}
}
