//go:build !arm && linux

package unix

import (
	"unsafe"

	linux "golang.org/x/sys/unix"
)

// TODO: Remove this file and wrap linux.MmapPtr in types_linux.go when upgrading to Go 1.23.
func MmapPtr(fd int, offset int64, addr unsafe.Pointer, length uintptr, prot int, flags int) (ret unsafe.Pointer, err error) {
	r0, _, e1 := linux.Syscall6(linux.SYS_MMAP, uintptr(addr), uintptr(length), uintptr(prot), uintptr(flags), uintptr(fd), uintptr(offset))
	if e1 != 0 {
		return unsafe.Pointer(nil), e1
	}
	return unsafe.Pointer(r0), nil
}
