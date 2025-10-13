package ringbuf

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/testutils"
)

func mustRun(tb testing.TB, prog *ebpf.Program) {
	tb.Helper()

	opts := &ebpf.RunOptions{
		Data: internal.EmptyBPFContext,
	}
	if platform.IsWindows {
		opts.Context = make([]byte, 32)
	}

	ret, err := prog.Run(opts)
	testutils.SkipIfNotSupported(tb, err)
	qt.Assert(tb, qt.IsNil(err))

	qt.Assert(tb, qt.Equals(ret, uint32(0)))
}
