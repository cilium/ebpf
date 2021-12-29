package link

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

type SocketFilterOptions struct {
	// Name of the interface to attach to.
	InterfaceName string

	// Program must be of type SocketFilter.
	Program *ebpf.Program
}

// AttachSocketFilter links a BPF program to an interface.
func AttachSocketFilter(opts SocketFilterOptions) (Link, error) {
	sockFD, err := rawSocket(opts.InterfaceName)
	if err != nil {
		return nil, err
	}

	if err := syscall.SetsockoptInt(sockFD, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, opts.Program.FD()); err != nil {
		syscall.Close(sockFD)
		return nil, err
	}

	return &linkSocketFilter{
		sockFD: sockFD,
	}, nil
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
	return syscall.Close(lsf.sockFD)
}

func (lsf *linkSocketFilter) isLink() {}

func rawSocket(ifName string) (int, error) {
	intf, err := net.InterfaceByName(ifName)
	if err != nil {
		return 0, err
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW|syscall.SOCK_NONBLOCK|syscall.SOCK_CLOEXEC, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, fmt.Errorf("open raw socket: %w", err)
	}
	sll := syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  intf.Index,
	}
	if err := syscall.Bind(fd, &sll); err != nil {
		return 0, fmt.Errorf("bind raw socket: %w", err)
	}
	return fd, nil
}

func htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return sys.HostByteorder.Uint16(b)
}
