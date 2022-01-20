package link

import (
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/unix"
)

// SocketFilterAttachProgram attaches a SocketFilter BPF program to a raw socket.
func SocketFilterAttachProgram(conn syscall.Conn, program *ebpf.Program) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var ssoErr error
	err = rawConn.Control(func(fd uintptr) {
		ssoErr = syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_ATTACH_BPF, program.FD())
	})
	if ssoErr != nil {
		return ssoErr
	}
	return err
}

// SocketFilterDetachProgram detaches a SocketFilter BPF program from a raw socket.
func SocketFilterDetachProgram(conn syscall.Conn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var ssoErr error
	err = rawConn.Control(func(fd uintptr) {
		ssoErr = syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_DETACH_BPF, 0)
	})
	if ssoErr != nil {
		return ssoErr
	}
	return err
}
