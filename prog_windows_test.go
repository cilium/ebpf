package ebpf

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal/efw"
)

const basicProgramType = WindowsXDPTest
const xdpProgramType = WindowsXDPTest

func dupFD(tb testing.TB, fd int) int {
	tb.Helper()

	dup, err := efw.EbpfDupFd(fd)
	qt.Assert(tb, qt.IsNil(err))

	return dup
}
