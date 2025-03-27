package ebpf

import (
	"runtime"
	"sync/atomic"
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

func TestCheckUnsafeMemory(t *testing.T) {
	mm, err := mustMmapableArray(t, 0).unsafeMemory()
	qt.Assert(t, qt.IsNil(err))

	// Primitive types
	qt.Assert(t, qt.IsNil(checkUnsafeMemory[bool](mm, 0)))
	qt.Assert(t, qt.IsNil(checkUnsafeMemory[uint32](mm, 0)))

	// Arrays
	qt.Assert(t, qt.IsNil(checkUnsafeMemory[[4]byte](mm, 0)))
	qt.Assert(t, qt.IsNil(checkUnsafeMemory[[2]struct {
		A uint32
		B uint64
	}](mm, 0)))

	// Structs
	qt.Assert(t, qt.IsNil(checkUnsafeMemory[struct{ _ uint32 }](mm, 0)))
	qt.Assert(t, qt.IsNil(checkUnsafeMemory[struct{ _ [4]byte }](mm, 0)))

	// Atomics
	qt.Assert(t, qt.IsNil(checkUnsafeMemory[atomic.Uint32](mm, 0)))

	// No pointers
	qt.Assert(t, qt.ErrorIs(checkUnsafeMemory[*uint32](mm, 0), ErrInvalidType))
	qt.Assert(t, qt.ErrorIs(checkUnsafeMemory[**uint32](mm, 0), ErrInvalidType))
	qt.Assert(t, qt.ErrorIs(checkUnsafeMemory[[1]*uint8](mm, 0), ErrInvalidType))
	qt.Assert(t, qt.ErrorIs(checkUnsafeMemory[struct{ _ *uint8 }](mm, 0), ErrInvalidType))

	// No variable-sized types
	qt.Assert(t, qt.ErrorIs(checkUnsafeMemory[int](mm, 0), ErrInvalidType))
	qt.Assert(t, qt.ErrorIs(checkUnsafeMemory[uint](mm, 0), ErrInvalidType))
	qt.Assert(t, qt.ErrorIs(checkUnsafeMemory[uintptr](mm, 0), ErrInvalidType))
	qt.Assert(t, qt.ErrorIs(checkUnsafeMemory[atomic.Uintptr](mm, 0), ErrInvalidType))
	qt.Assert(t, qt.ErrorIs(checkUnsafeMemory[struct{ _ uintptr }](mm, 0), ErrInvalidType))

	// No interface types
	qt.Assert(t, qt.ErrorIs(checkUnsafeMemory[any](mm, 0), ErrInvalidType))

	// No zero-sized types
	qt.Assert(t, qt.ErrorIs(checkUnsafeMemory[struct{}](mm, 0), ErrInvalidType))
}
