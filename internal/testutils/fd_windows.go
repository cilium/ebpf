package testutils

import (
	"testing"

	"github.com/cilium/ebpf/internal/efw"
	"github.com/go-quicktest/qt"
)

func DupFD(tb testing.TB, fd int) int {
	tb.Helper()

	dup, err := efw.EbpfDuplicateFd(fd)
	qt.Assert(tb, qt.IsNil(err))

	return dup
}
