package link

import (
	"fmt"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/unix"
)

type SocketFilterOptions struct {
	// File descriptor of the raw socket.
	SockFD int

	// Program must be of type SocketFilter.
	Program *ebpf.Program
}

// AttachSocketFilter links a BPF program to a raw socket.
func AttachSocketFilter(opts SocketFilterOptions) (Link, error) {
	if err := syscall.SetsockoptInt(opts.SockFD, unix.SOL_SOCKET, unix.SO_ATTACH_BPF, opts.Program.FD()); err != nil {
		return nil, err
	}
	return &linkSocketFilter{sockFD: opts.SockFD}, nil
}

type linkSocketFilter struct {
	sockFD int
}

var _ Link = (*linkSocketFilter)(nil)

func (lsf *linkSocketFilter) Update(prog *ebpf.Program) error {
	return syscall.SetsockoptInt(lsf.sockFD, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, prog.FD())
}

func (lsf *linkSocketFilter) Pin(string) error {
	return fmt.Errorf("can't pin socket filter: %w", ErrNotSupported)
}

func (lsf *linkSocketFilter) Unpin() error {
	return fmt.Errorf("can't unpin socket filter: %w", ErrNotSupported)
}

func (lsf *linkSocketFilter) Info() (*Info, error) {
	return nil, fmt.Errorf("can't get socket filter info: %w", ErrNotSupported)
}

func (lsf *linkSocketFilter) Close() error {
	return syscall.SetsockoptInt(lsf.sockFD, syscall.SOL_SOCKET, unix.SO_DETACH_BPF, 0)
}

func (lsf *linkSocketFilter) isLink() {}
