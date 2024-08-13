package ebpf

import (
	"fmt"
	"io"
	"sync/atomic"
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"
)

type Memory struct {
	// Pointer to the memory-mapped region.
	b  []byte
	ro bool
}

func (mm *Memory) Size() int {
	return len(mm.b)
}

func (mm *Memory) close() error {
	if err := unix.Munmap(mm.b); err != nil {
		return fmt.Errorf("unmapping memory-mapped region: %w", err)
	}

	mm.b = nil

	return nil
}

func (mm *Memory) ReadAt(p []byte, off int64) (int, error) {
	if mm.b == nil {
		return 0, fmt.Errorf("memory-mapped region closed")
	}

	if p == nil {
		return 0, fmt.Errorf("input buffer p is nil")
	}

	if off < 0 || off >= int64(len(mm.b)) {
		return 0, fmt.Errorf("read offset out of range")
	}

	n := copy(p, mm.b[off:])
	if n < len(p) {
		return n, io.EOF
	}

	return n, nil
}

func (mm *Memory) WriteAt(p []byte, off int64) (int, error) {
	if mm.b == nil {
		return 0, fmt.Errorf("memory-mapped region closed")
	}
	if mm.ro {
		return 0, fmt.Errorf("memory-mapped region is read-only")
	}

	if p == nil {
		return 0, fmt.Errorf("output buffer p is nil")
	}

	if off < 0 || off >= int64(len(mm.b)) {
		return 0, fmt.Errorf("write offset out of range")
	}

	n := copy(mm.b[off:], p)
	if n < len(p) {
		return n, io.EOF
	}

	return n, nil
}

// Uint32 provides atomic access to a uint32 in a memory-mapped region.
type Uint32 struct {
	*atomic.Uint32
	mm *Memory
}

// Uint64 provides atomic access to a uint64 in a memory-mapped region.
type Uint64 struct {
	*atomic.Uint64
	mm *Memory
}

// Int32 provides atomic access to an int32 in a memory-mapped region.
type Int32 struct {
	*atomic.Int32
	mm *Memory
}

// Int64 provides atomic access to an int64 in a memory-mapped region.
type Int64 struct {
	*atomic.Int64
	mm *Memory
}

// checkMemory ensures a T can be accessed in mm at offset off. Returns an error
// if mm is read-only.
func checkMemory[T any](mm *Memory, off uint64) error {
	var t T
	if mm.b == nil {
		return fmt.Errorf("memory-mapped region closed")
	}
	if mm.ro {
		return fmt.Errorf("memory-mapped region is read-only")
	}
	vs, bs := uint64(unsafe.Sizeof(t)), uint64(len(mm.b))
	if off+vs > bs {
		return fmt.Errorf("%d-byte write at offset %d exceeds mmap size of %d bytes", vs, off, bs)
	}
	return nil
}

// reinterp reinterprets a pointer of type In to a pointer of type Out.
func reinterp[Out, In any](in *In) *Out {
	return (*Out)(unsafe.Pointer(in))
}

// AtomicUint32 returns an atomic accessor to a uint32 in the memory-mapped
// region at offset off.
//
// It's not possible to obtain an accessor for a read-only region.
func (mm *Memory) AtomicUint32(off uint64) (r *Uint32, err error) {
	if err := checkMemory[atomic.Uint32](mm, off); err != nil {
		return nil, err
	}
	return &Uint32{reinterp[atomic.Uint32](&mm.b[off]), mm}, nil
}

// AtomicInt32 returns an atomic accessor to an int32 in the memory-mapped
// region at offset off.
//
// It's not possible to obtain an accessor for a read-only region.
func (mm *Memory) AtomicInt32(off uint64) (r *Int32, err error) {
	if err := checkMemory[atomic.Int32](mm, off); err != nil {
		return nil, err
	}
	return &Int32{reinterp[atomic.Int32](&mm.b[off]), mm}, nil
}

// AtomicUint64 returns an atomic accessor to a uint64 in the memory-mapped
// region at offset off.
//
// It's not possible to obtain an accessor for a read-only region.
func (mm *Memory) AtomicUint64(off uint64) (r *Uint64, err error) {
	if err := checkMemory[atomic.Uint64](mm, off); err != nil {
		return nil, err
	}
	return &Uint64{reinterp[atomic.Uint64](&mm.b[off]), mm}, nil
}

// AtomicInt64 returns an atomic accessor to an int64 in the memory-mapped
// region at offset off.
//
// It's not possible to obtain an accessor for a read-only region.
func (mm *Memory) AtomicInt64(off uint64) (r *Int64, err error) {
	if err := checkMemory[atomic.Int64](mm, off); err != nil {
		return nil, err
	}
	return &Int64{reinterp[atomic.Int64](&mm.b[off]), mm}, nil
}
