package ebpf

import (
	"io"
	"os"
	"runtime"
	"testing"
	"unsafe"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
)

func mustMmapableArray(tb testing.TB, extraFlags uint32) *Map {
	tb.Helper()

	m, err := NewMap(&MapSpec{
		Name:       "ebpf_mmap",
		Type:       Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 8,
		Flags:      sys.BPF_F_MMAPABLE | extraFlags,
	})
	testutils.SkipIfNotSupported(tb, err)
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() {
		m.Close()
	})
	return m
}

func TestMemory(t *testing.T) {
	mm, err := mustMmapableArray(t, 0).Memory()
	qt.Assert(t, qt.IsNil(err))

	// The mapping is always at least one page long, and the Map created here fits
	// in a single page.
	qt.Assert(t, qt.Equals(mm.Size(), os.Getpagesize()))

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

func TestMemoryUnmap(t *testing.T) {
	mm, err := mustMmapableArray(t, 0).Memory()
	qt.Assert(t, qt.IsNil(err))

	ptr := unsafe.SliceData(mm.b)

	// Avoid unmap running twice, which would discard the contents of the Go
	// heap where the mapping used to be, potentially corrupting it.
	runtime.SetFinalizer(ptr, nil)

	// unmap panics if the operation fails.
	unmap(mm.Size())(ptr)
}
