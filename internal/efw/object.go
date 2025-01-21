//go:build windows

package efw

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

/*
Retrieve object info and type from a fd.

	ebpf_result_t ebpf_object_get_info_by_fd(
		fd_t bpf_fd,
		_Inout_updates_bytes_to_opt_(*info_size, *info_size) void* info,
		_Inout_opt_ uint32_t* info_size,
		_Out_opt_ ebpf_object_type_t* type)
*/
var ebpfObjectGetInfoByFdProc = newProc("ebpf_object_get_info_by_fd")

func EbpfObjectGetInfoByFd(fd int, info unsafe.Pointer, info_size *uint32) (ObjectType, error) {
	addr, err := ebpfObjectGetInfoByFdProc.Find()
	if err != nil {
		return 0, err
	}

	var objectType ObjectType
	err = errorResult(syscall.SyscallN(addr,
		uintptr(fd),
		uintptr(info),
		uintptr(unsafe.Pointer(info_size)),
		uintptr(unsafe.Pointer(&objectType)),
	))
	return objectType, err
}

// ebpf_result_t ebpf_object_unpin(_In_z_ const char* path)
var ebpfObjectUnpinProc = newProc("ebpf_object_unpin")

func EbpfObjectUnpin(path string) error {
	addr, err := ebpfObjectUnpinProc.Find()
	if err != nil {
		return err
	}

	pathBytes, err := windows.ByteSliceFromString(path)
	if err != nil {
		return err
	}

	return errorResult(syscall.SyscallN(addr, uintptr(unsafe.Pointer(&pathBytes[0]))))
}
