package ebpf

import (
	"io"
	"math"
	"os"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
)

func mustMmapableArray(tb testing.TB, extraFlags uint32) *Map {
	tb.Helper()

	m, err := newMap(tb, &MapSpec{
		Name:       "ebpf_mmap",
		Type:       Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 8,
		Flags:      sys.BPF_F_MMAPABLE | extraFlags,
	}, nil)
	testutils.SkipIfNotSupported(tb, err)
	qt.Assert(tb, qt.IsNil(err))
	return m
}

func TestMemory(t *testing.T) {
	mm, err := mustMmapableArray(t, 0).Memory()
	qt.Assert(t, qt.IsNil(err))

	// The mapping is always at least one page long, and the Map created here fits
	// in a single page.
	qt.Assert(t, qt.Equals(mm.Size(), os.Getpagesize()))

	// No BPF_F_RDONLY_PROG flag, so the Memory should be read-write.
	qt.Assert(t, qt.IsFalse(mm.ReadOnly()))

	want := []byte{1, 2, 3, 4, 4, 3, 2, 1}
	w := io.NewOffsetWriter(mm, 16)
	n, err := w.Write(want)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(n, 8))

	r := io.NewSectionReader(mm, 16, int64(len(want)))
	got := make([]byte, len(want))
	n, err = r.Read(got)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(n, len(want)))
}

func TestMemoryBounds(t *testing.T) {
	mm, err := mustMmapableArray(t, 0).Memory()
	qt.Assert(t, qt.IsNil(err))

	end := uint64(mm.Size())

	qt.Assert(t, qt.IsTrue(mm.bounds(0, 0)))
	qt.Assert(t, qt.IsTrue(mm.bounds(end, 0)))
	qt.Assert(t, qt.IsTrue(mm.bounds(end-8, 8)))
	qt.Assert(t, qt.IsTrue(mm.bounds(0, end)))

	qt.Assert(t, qt.IsFalse(mm.bounds(end-8, 9)))
	qt.Assert(t, qt.IsFalse(mm.bounds(end, 1)))
	qt.Assert(t, qt.IsFalse(mm.bounds(math.MaxUint64, 1)))
}

func TestMemoryReadOnly(t *testing.T) {
	rd, err := mustMmapableArray(t, sys.BPF_F_RDONLY_PROG).Memory()
	qt.Assert(t, qt.IsNil(err))

	// BPF_F_RDONLY_PROG flag, so the Memory should be read-only.
	qt.Assert(t, qt.IsTrue(rd.ReadOnly()))

	// Frozen maps can't be mapped rw either.
	frozen := mustMmapableArray(t, 0)
	qt.Assert(t, qt.IsNil(frozen.Freeze()))
	fz, err := frozen.Memory()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(fz.ReadOnly()))
}

func TestMemoryClose(t *testing.T) {
	mm, err := mustMmapableArray(t, 0).Memory()
	qt.Assert(t, qt.IsNil(err))

	// unmap panics if the operation fails.
	mm.close()
}
