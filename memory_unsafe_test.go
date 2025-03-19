package ebpf

import (
	"runtime"
	"testing"
	"unsafe"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal/sys"
)

func TestUnsafeMemoryUnmap(t *testing.T) {
	mm, err := mustMmapableArray(t, 0).unsafeMemory()
	qt.Assert(t, qt.IsNil(err))

	// Avoid unmap running twice.
	runtime.SetFinalizer(unsafe.SliceData(mm.b), nil)

	// unmap panics if the operation fails.
	unmap(mm.Size())(unsafe.SliceData(mm.b))
}

func TestUnsafeMemoryPointer(t *testing.T) {
	mm, err := mustMmapableArray(t, 0).unsafeMemory()
	qt.Assert(t, qt.IsNil(err))

	// Requesting an unaligned value should fail.
	_, err = memoryPointer[uint32](mm, 7)
	qt.Assert(t, qt.IsNotNil(err))

	u32, err := memoryPointer[uint32](mm, 12)
	qt.Assert(t, qt.IsNil(err))

	*u32 = 0xf00d
	qt.Assert(t, qt.Equals(*u32, 0xf00d))

	_, err = memoryPointer[*uint32](mm, 0)
	qt.Assert(t, qt.ErrorIs(err, ErrInvalidType))
}

func TestUnsafeMemoryReadOnly(t *testing.T) {
	rd, err := mustMmapableArray(t, sys.BPF_F_RDONLY_PROG).unsafeMemory()
	qt.Assert(t, qt.IsNil(err))

	// BPF_F_RDONLY_PROG flag, so the Memory should be read-only.
	qt.Assert(t, qt.IsTrue(rd.ReadOnly()))

	// Frozen maps can't be mapped rw either.
	frozen := mustMmapableArray(t, 0)
	qt.Assert(t, qt.IsNil(frozen.Freeze()))
	fz, err := frozen.Memory()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(fz.ReadOnly()))

	_, err = fz.WriteAt([]byte{1}, 0)
	qt.Assert(t, qt.ErrorIs(err, ErrReadOnly))

	_, err = memoryPointer[uint32](fz, 0)
	qt.Assert(t, qt.ErrorIs(err, ErrReadOnly))
}
