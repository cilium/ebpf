//go:build !windows

package testutils

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal/unix"
)

func DupFD(tb testing.TB, fd int) int {
	tb.Helper()

	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 1)
	qt.Assert(tb, qt.IsNil(err))

	return dup
}
