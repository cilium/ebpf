package sys

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"
)

// BPF wraps SYS_BPF.
//
// Any pointers contained in attr must use the Pointer type from this package.
func BPF(cmd Cmd, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	r1, _, errNo := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
	runtime.KeepAlive(attr)

	var err error
	if errNo != 0 {
		err = wrappedErrno{errNo}
	}

	return r1, err
}

// ProgLoad wraps BPF_PROG_LOAD.
func ProgLoad(attr *ProgLoadAttr) (*FD, error) {
	for {
		fd, err := BPF(BPF_PROG_LOAD, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
		// As of ~4.20 the verifier can be interrupted by a signal,
		// and returns EAGAIN in that case.
		if errors.Is(err, unix.EAGAIN) {
			continue
		}

		if err != nil {
			return nil, err
		}

		return NewFD(int(fd)), nil
	}
}

func ProgAttach(attr *ProgAttachAttr) error {
	_, err := BPF(BPF_PROG_ATTACH, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func ProgDetach(attr *ProgAttachAttr) error {
	_, err := BPF(BPF_PROG_DETACH, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

func EnableStats(attr *EnableStatsAttr) (*FD, error) {
	ptr, err := BPF(BPF_ENABLE_STATS, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, fmt.Errorf("enable stats: %w", err)
	}
	return NewFD(int(ptr)), nil

}

// ObjPin wraps BPF_OBJ_PIN.
func ObjPin(fileName string, fd *FD) error {
	attr := ObjPinAttr{
		Pathname: NewStringPointer(fileName),
		BpfFd:    fd.Uint(),
	}
	_, err := BPF(BPF_OBJ_PIN, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return fmt.Errorf("pin object %s: %w", fileName, err)
	}
	return nil
}

// ObjGet wraps BPF_OBJ_GET.
func ObjGet(fileName string, flags uint32) (*FD, error) {
	attr := ObjPinAttr{
		Pathname:  NewStringPointer(fileName),
		FileFlags: flags,
	}
	ptr, err := BPF(BPF_OBJ_GET, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return nil, fmt.Errorf("get object %s: %w", fileName, err)
	}
	return NewFD(int(ptr)), nil
}

// ObjGetInfoByFD wraps BPF_OBJ_GET_INFO_BY_FD.
//
// Available from 4.13.
func ObjGetInfoByFD(fd *FD, info unsafe.Pointer, size uintptr) error {
	attr := ObjGetInfoByFdAttr{
		BpfFd:   fd.Uint(),
		InfoLen: uint32(size),
		Info:    NewPointer(info),
	}
	_, err := BPF(BPF_OBJ_GET_INFO_BY_FD, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if err != nil {
		return fmt.Errorf("fd %v: %w", fd, err)
	}
	return nil
}

// ObjGetFDByID wraps BPF_*_GET_FD_BY_ID.
//
// Available from 4.13.
func ObjGetFDByID(cmd Cmd, id uint32) (*FD, error) {
	attr := MapGetFdByIdAttr{
		Id: id,
	}
	ptr, err := BPF(cmd, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return NewFD(int(ptr)), err
}

// BPFObjName is a null-terminated string made up of
// 'A-Za-z0-9_' characters.
type ObjName [unix.BPF_OBJ_NAME_LEN]byte

// NewObjName truncates the result if it is too long.
func NewObjName(name string) ObjName {
	var result ObjName
	copy(result[:unix.BPF_OBJ_NAME_LEN-1], name)
	return result
}

func MapCreate(attr *MapCreateAttr) (*FD, error) {
	fd, err := BPF(BPF_MAP_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}

	return NewFD(int(fd)), nil
}

// wrappedErrno wraps syscall.Errno to prevent direct comparisons with
// syscall.E* or unix.E* constants.
//
// You should never export an error of this type.
type wrappedErrno struct {
	syscall.Errno
}

func (we wrappedErrno) Unwrap() error {
	return we.Errno
}

type syscallError struct {
	error
	errno syscall.Errno
}

func Error(err error, errno syscall.Errno) error {
	return &syscallError{err, errno}
}

func (se *syscallError) Is(target error) bool {
	return target == se.error
}

func (se *syscallError) Unwrap() error {
	return se.errno
}
