package sys

import (
	"math"
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"
)

// UnsafePointer creates a 64-bit pointer from an unsafe Pointer.
func UnsafePointer(ptr unsafe.Pointer) Pointer {
	return Pointer{ptr: ptr}
}

// SlicePointer creates a 64-bit pointer from a slice.
func SlicePointer[E any](slice []E) Pointer {
	if len(slice) == 0 {
		return Pointer{}
	}

	return Pointer{ptr: unsafe.Pointer(&slice[0])}
}

// SliceLen returns the length of a slice as a uint32.
//
// Returns zero if the length of the slice exceeds uint32.
func SliceLen[E any](slice []E) uint32 {
	return SliceElems(slice, 1)
}

// SliceElems returns the number of equal sized elements in a slice.
//
// Returns zero if the number of elements exceeds uint32.
func SliceElems[E any](slice []E, elemSize int) uint32 {
	n := len(slice) / elemSize
	if int64(n) > math.MaxUint32 {
		return 0
	}

	return uint32(n)
}

// NewStringPointer allocates a null-terminated backing slice for str and returns
// a pointer to it.
func NewStringPointer(str string) Pointer {
	s, err := unix.ByteSliceFromString(str)
	if err != nil {
		return Pointer{}
	}

	return SlicePointer(s)
}

// NewStringSlicePointer allocates an array of Pointers for each string in the
// given slice of strings and returns a 64-bit pointer to the start of the
// resulting array.
//
// Use this function to pass arrays of strings as syscall arguments.
func NewStringSlicePointer(strings []string) Pointer {
	sp := make([]Pointer, 0, len(strings))
	for _, s := range strings {
		sp = append(sp, NewStringPointer(s))
	}

	return SlicePointer(sp)
}
