package btf

import (
	"fmt"

	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

// Info describes a Handle.
type Info struct {
	ID ID
	// Name is an identifying name for the BTF, currently only used by the
	// kernel.
	Name string

	// KernelBTF is true if the BTF originated with the kernel and not
	// userspace.
	KernelBTF bool

	// Size of the raw BTF in bytes.
	size uint32
}

func newInfoFromFd(fd *sys.FD) (*Info, error) {
	// We invoke the syscall once with a empty BTF and name buffers to get size
	// information to allocate buffers. Then we invoke it a second time with
	// buffers to receive the data.
	var btfInfo sys.BtfInfo
	if err := sys.ObjInfo(fd, &btfInfo); err != nil {
		return nil, fmt.Errorf("get BTF info for fd %s: %w", fd, err)
	}

	if btfInfo.NameLen > 0 {
		// NameLen doesn't account for the terminating NUL.
		btfInfo.NameLen++
	}

	// Don't pull raw BTF by default, since it may be quite large.
	btfSize := btfInfo.BtfSize
	btfInfo.BtfSize = 0

	nameBuffer := make([]byte, btfInfo.NameLen)
	btfInfo.Name, btfInfo.NameLen = sys.NewSlicePointerLen(nameBuffer)
	if err := sys.ObjInfo(fd, &btfInfo); err != nil {
		return nil, err
	}

	return &Info{
		ID:        btfInfo.Id,
		Name:      unix.ByteSliceToString(nameBuffer),
		KernelBTF: btfInfo.KernelBtf != 0,
		size:      btfSize,
	}, nil
}

// IsModule returns true if the BTF is for the kernel itself.
func (i *Info) IsVmlinux() bool {
	return i.KernelBTF && i.Name == "vmlinux"
}

// IsModule returns true if the BTF is for a kernel module.
func (i *Info) IsModule() bool {
	return i.KernelBTF && i.Name != "vmlinux"
}
