package sys

import (
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/efw"
	"golang.org/x/sys/windows"
)

var (
	// int bpf(int cmd, union bpf_attr* attr, unsigned int size)
	bpfProc = efw.Module.NewProc("bpf")
)

// BPF calls the BPF syscall wrapper in ebpfapi.dll.
//
// Any pointers contained in attr must use the Pointer type from this package.
//
// The implementation lives in https://github.com/microsoft/ebpf-for-windows/blob/main/libs/api/bpf_syscall.cpp
func BPF(cmd Cmd, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	// On Linux we need to guard against preemption by the profiler here. On
	// Windows it seems like a cgocall may not be preempted:
	// https://github.com/golang/go/blob/8b51146c698bcfcc2c2b73fa9390db5230f2ce0a/src/runtime/os_windows.go#L1240-L1246

	if err := bpfProc.Find(); err != nil {
		return 0, err
	}

	// Using bpfProc.Call forces attr to escape, which isn't the case when using syscall.Syscall directly.
	// We're not using SyscallN since that causes the slice parameter to escape to the heap.
	r1, _, lastError := syscall.Syscall(bpfProc.Addr(), 3, uintptr(cmd), uintptr(attr), size)

	// On MSVC (x64, arm64) and MinGW (gcc, clang) sizeof(int) is 4.
	ret := int(int32(r1))
	if ret < 0 {
		errno := Errno(-ret)
		if errno == EINVAL && lastError == windows.ERROR_CALL_NOT_IMPLEMENTED {
			return 0, internal.ErrNotSupported
		}
		return 0, errnoErr(errno)
	}

	return r1, nil
}
