package sys

import (
	"os"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/internal/unix"
	qt "github.com/frankban/quicktest"
)

func init() {
	// Free up fd 0 for TestFD.
	stdin, err := unix.FcntlInt(os.Stdin.Fd(), unix.F_DUPFD_CLOEXEC, 1)
	if err != nil {
		panic(err)
	}

	old := os.Stdin
	os.Stdin = os.NewFile(uintptr(stdin), "stdin")
	old.Close()

	reserveFdZero()
}

func reserveFdZero() {
	fd, err := unix.Open(os.DevNull, syscall.O_RDONLY, 0)
	if err != nil {
		panic(err)
	}
	if fd != 0 {
		panic(err)
	}
}

func TestFD(t *testing.T) {
	_, err := NewFD(-1)
	qt.Assert(t, err, qt.IsNotNil, qt.Commentf("negative fd should be rejected"))

	fd, err := NewFD(0)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, fd.Int(), qt.Not(qt.Equals), 0, qt.Commentf("fd value should not be zero"))

	var stat unix.Stat_t
	err = unix.Fstat(0, &stat)
	qt.Assert(t, err, qt.ErrorIs, unix.EBADF, qt.Commentf("zero fd should be closed"))

	reserveFdZero()
}

func TestFDFile(t *testing.T) {
	fd := newFD(openFd(t))
	file := fd.File("test")
	qt.Assert(t, file, qt.IsNotNil)
	qt.Assert(t, file.Close(), qt.IsNil)
	qt.Assert(t, fd.File("closed"), qt.IsNil)

	_, err := fd.Dup()
	qt.Assert(t, err, qt.ErrorIs, ErrClosedFd)
}

func openFd(tb testing.TB) int {
	fd, err := unix.Open(os.DevNull, syscall.O_RDONLY, 0)
	qt.Assert(tb, err, qt.IsNil)
	return fd
}
