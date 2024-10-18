//go:build windows

package efw

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ebpf_result_t ebpf_close_fd(fd_t fd)
var ebpfCloseFdProc = newProc("ebpf_close_fd")

func EbpfCloseFd(fd int) error {
	return ebpfCloseFdProc.CallResult(uintptr(fd))
}

// ebpf_result_t ebpf_dup_fd(fd_t fd, _Out_ fd_t* dup)
var ebpfDupFdProc = newProc("ebpf_dup_fd")

func EbpfDupFd(fd int) (int, error) {
	var dup FD
	err := ebpfDupFdProc.CallResult(uintptr(fd), uintptr(unsafe.Pointer(&dup)))
	return int(dup), err
}

// ebpf_result_t ebpf_object_unpin(_In_z_ const char* path)
var ebpfObjectUnpinProc = newProc("ebpf_object_unpin")

func EbpfObjectUnpin(path string) error {
	pathBytes, err := windows.ByteSliceFromString(path)
	if err != nil {
		return err
	}

	return ebpfObjectUnpinProc.CallResult(uintptr(unsafe.Pointer(&pathBytes[0])))
}

/*
ebpf_result_t ebpf_object_load_native_fds(

	_In_z_ const char* file_name,
	_Inout_ size_t* count_of_maps,
	_Out_writes_opt_(count_of_maps) fd_t* map_fds,
	_Inout_ size_t* count_of_programs,
	_Out_writes_opt_(count_of_programs) fd_t* program_fds)
*/
var ebpfObjectLoadNativeFdsProc = newProc("ebpf_object_load_native_fds")

func EbpfObjectLoadNativeFds(fileName string, mapFds []FD, programFds []FD) (int, int, error) {
	fileBytes, err := windows.ByteSliceFromString(fileName)
	if err != nil {
		return 0, 0, err
	}

	countOfMaps := size(len(mapFds))
	countOfPrograms := size(len(programFds))
	err = ebpfObjectLoadNativeFdsProc.CallResult(
		uintptr(unsafe.Pointer(&fileBytes[0])),
		uintptr(unsafe.Pointer(&countOfMaps)),
		uintptr(unsafe.Pointer(&mapFds[0])),
		uintptr(unsafe.Pointer(&countOfPrograms)),
		uintptr(unsafe.Pointer(&programFds[0])),
	)

	return int(countOfMaps), int(countOfPrograms), err
}

// int bpf(int cmd, union bpf_attr* attr, unsigned int size)
var BPF = newProc("bpf")

// ebpf_result_t ebpf_program_attach_by_fd(
// fd_t program_fd,
// _In_opt_ const ebpf_attach_type_t* attach_type,
// _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
// size_t attach_parameters_size,
// _Outptr_ struct bpf_link** link)
var ebpfProgramAttachByFdProc = newProc("ebpf_program_attach_by_fd")

func EbpfProgramAttachByFd(fd int, attachType *windows.GUID) (int, error) {
	var link uintptr
	err := ebpfProgramAttachByFdProc.CallResult(
		uintptr(fd),
		uintptr(unsafe.Pointer(attachType)),
		0, // attach_parameters
		0, // attach_parameters_size
		uintptr(unsafe.Pointer(&link)),
	)
	if err != nil {
		return -1, err
	}

	return EbpfLinkFd(link)
}

// fd_t ebpf_link_fd(_Frees_ptr_ struct bpf_link* link)
var ebpfLinkFdProc = newProc("ebpf_link_free")

func EbpfLinkFd(link uintptr) (int, error) {
	return ebpfLinkFdProc.CallFd(link)
}

// const ebpf_attach_type_t* ebpf_get_ebpf_attach_type(bpf_attach_type_t bpf_attach_type)
var ebpfGetEbpfAttachTypeProc = newProc("ebpf_get_ebpf_attach_type")

func EbpfGetEbpfAttachType(attachType uint32) (windows.GUID, error) {
	attachTypeGUID, err := ebpfGetEbpfAttachTypeProc.CallPointer(uintptr(attachType))
	if err != nil {
		return windows.GUID{}, err
	}

	// The efW runtime returns a pointer to a dynamically allocated GUID.
	// This seems a bit dodgy, so convert it to an object managed by the Go runtime.
	// It'd be nice if that was possible without violating the unsafe.Pointer rules.
	return *((*windows.GUID)(unsafe.Pointer(attachTypeGUID))), nil
}

type proc struct {
	*windows.LazyProc
}

func newProc(name string) proc {
	return proc{module.NewProc(name)}
}

func (p proc) Find() error {
	err := p.LazyProc.Find()
	if errors.Is(err, windows.ERROR_MOD_NOT_FOUND) {
		return fmt.Errorf("load %s: not found", module.Name)
	}
	return err
}

// Call a function which returns a C int.
//
//go:uintptrescapes
func (p proc) CallInt(args ...uintptr) (int, windows.Errno, error) {
	if err := p.Find(); err != nil {
		return 0, 0, fmt.Errorf("%s: %w", p.Name, err)
	}

	res, _, err := p.Call(args...)
	return int(int32(res)), err.(windows.Errno), nil
}

// Call a function which returns ebpf_result_t.
//
//go:uintptrescapes
func (p proc) CallResult(args ...uintptr) error {
	if err := p.Find(); err != nil {
		return fmt.Errorf("%s: %w", p.Name, err)
	}

	res, _, errNo := p.Call(args...)
	if err := ResultToError(Result(res)); err != nil {
		if errNo.(syscall.Errno) != 0 {
			return fmt.Errorf("%s: %w (errno: %v)", p.Name, err, errNo)
		}
		return fmt.Errorf("%s: %w", p.Name, err)
	}
	return nil
}

// Call a function which returns fd_t.
//
//go:uintptrescapes
func (p proc) CallFd(args ...uintptr) (int, error) {
	if err := p.Find(); err != nil {
		return -1, fmt.Errorf("%s: %w", p.Name, err)
	}

	res, _, _ := p.Call(args...)
	return int(FD(res)), nil
}

// Call a function which returns a pointer to C managed memory.
//
//go:uintptrescapes
func (p proc) CallPointer(args ...uintptr) (uintptr, error) {
	if err := p.Find(); err != nil {
		return 0, fmt.Errorf("%s: %w", p.Name, err)
	}

	res, _, _ := p.Call(args...)
	return res, nil
}
