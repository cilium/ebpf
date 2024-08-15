package sys

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/internal/efw"
)

// FD wraps a handle which is managed by the eBPF for Windows runtime.
//
// It is not equivalent to a real file descriptor or handle.
type FD struct {
	raw int
}

// NewFD wraps a raw fd with a finalizer.
//
// You must not use the raw fd after calling this function.
func NewFD(value int) (*FD, error) {
	if value == invalidFd {
		return nil, fmt.Errorf("invalid fd %d", value)
	}

	if value == 0 {
		// The bpf() syscall API can't deal with zero fds but we can't dup because
		// the handle is managed by efW.
		return nil, fmt.Errorf("invalid zero fd")
	}

	return newFD(value), nil
}

// ebpf_result_t ebpf_close_fd(fd_t fd)
var closeFdProc = efw.Module.NewProc("ebpf_close_fd")

// ebpf_result_t ebpf_dup_fd(fd_t fd, _Out_ fd_t* dup)
var dupFdProc = efw.Module.NewProc("ebpf_dup_fd")

func (fd *FD) Close() error {
	if fd.raw == invalidFd {
		return nil
	}

	return efw.CallResult(closeFdProc, uintptr(fd.disown()))
}

func (fd *FD) Dup() (*FD, error) {
	if fd.raw == invalidFd {
		return nil, ErrClosedFd
	}

	var dup efw.FD
	err := efw.CallResult(dupFdProc, uintptr(fd.raw), uintptr(unsafe.Pointer(&dup)))
	if err != nil {
		return nil, err
	}

	return NewFD(int(dup))
}
