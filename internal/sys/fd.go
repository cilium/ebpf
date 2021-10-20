package sys

import (
	"fmt"
	"math"
	"os"
	"runtime"
	"strconv"

	"github.com/cilium/ebpf/internal/unix"
)

var ErrClosedFd = unix.EBADF

type FD struct {
	raw int
}

func NewFD(value int) *FD {
	fd := &FD{value}
	runtime.SetFinalizer(fd, (*FD).Close)
	return fd
}

func (fd *FD) String() string {
	return strconv.FormatInt(int64(fd.raw), 10)
}

func (fd *FD) Int() int {
	return fd.raw
}

func (fd *FD) Uint() uint32 {
	if fd.raw < 0 || int64(fd.raw) > math.MaxUint32 {
		// Best effort: this is the number most likely to be an invalid file
		// descriptor. It is equal to -1 (on two's complement arches).
		return math.MaxUint32
	}
	return uint32(fd.raw)
}

func (fd *FD) Close() error {
	if fd.raw < 0 {
		return nil
	}

	value := int(fd.raw)
	fd.raw = -1

	fd.Forget()
	return unix.Close(value)
}

func (fd *FD) Forget() {
	runtime.SetFinalizer(fd, nil)
}

func (fd *FD) Dup() (*FD, error) {
	if fd.raw < 0 {
		return nil, ErrClosedFd
	}

	dup, err := unix.FcntlInt(uintptr(fd.raw), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("can't dup fd: %v", err)
	}

	return NewFD(dup), nil
}

func (fd *FD) File(name string) *os.File {
	fd.Forget()
	return os.NewFile(uintptr(fd.raw), name)
}
