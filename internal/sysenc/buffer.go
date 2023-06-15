package sysenc

import (
	"unsafe"

	"github.com/cilium/ebpf/internal/sys"
)

type Buffer struct {
	ptr    unsafe.Pointer
	layout dataLayout
}

func newBuffer(buf []byte, layout dataLayout) Buffer {
	if len(buf) == 0 {
		return Buffer{}
	}
	return Buffer{unsafe.Pointer(&buf[0]), layout}
}

// UnsafeBuffer constructs a Buffer for zero-copy unmarshaling.
//
// [Pointer] is the only valid method to call on such a Buffer.
// Use [SyscallBuffer] instead if possible.
func UnsafeBuffer(ptr unsafe.Pointer) Buffer {
	return Buffer{ptr, invalidLayout}
}

// SyscallOutput prepares a Buffer for a syscall to write into.
//
// The buffer may point at the underlying memory of dst, in which case [Unmarshal]
// becomes a no-op.
//
// The contents of the buffer are undefined and may be non-zero.
func SyscallOutput(dst any, size int) Buffer {
	layout := dataLayout{1, size, size}
	if dstBuf := unsafeBackingMemory(dst, layout); dstBuf != nil {
		return newBuffer(dstBuf, invalidLayout)
	}

	return newBuffer(make([]byte, layout.length()), layout)
}

// Copy the contents into dst.
//
// Returns the number of copied bytes.
func (b Buffer) Copy(dst []byte) int {
	return copy(dst, b.unsafeBytes())
}

// Pointer returns the location where a syscall should write.
func (b Buffer) Pointer() sys.Pointer {
	// NB: This deliberately ignores b.layout.valid() to support zero-copy
	// marshaling / unmarshaling using unsafe.Pointer.
	return sys.NewPointer(b.ptr)
}

// Unmarshal the buffer into the provided value.
//
// This is a no-op on a zero buffer.
func (b Buffer) Unmarshal(data any) error {
	if !b.layout.valid() {
		return nil
	}

	return Unmarshal(data, b.unsafeBytes())
}

func (b Buffer) unsafeBytes() []byte {
	return unsafe.Slice((*byte)(b.ptr), b.layout.length())
}
