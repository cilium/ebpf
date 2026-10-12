package ringbuf

import (
	"testing"
	"time"

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

func mustRunN(b *testing.B, prog *ebpf.Program, repeat uint32) time.Duration {
	b.Helper()

	ret, d, err := prog.Benchmark(b, int(repeat), internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(b, err)
	qt.Assert(b, qt.IsNil(err))

	qt.Assert(b, qt.Equals(ret, uint32(0)))

	return d
}
