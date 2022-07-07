package btf

import (
	"fmt"

	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

// HandleInfo describes a Handle.
type HandleInfo struct {
	// ID of this handle in the kernel. The ID is only valid as long as the
	// associated handle is kept alive.
	ID ID

	// Name is an identifying name for the BTF, currently only used by the
	// kernel.
	Name string

	// IsKernel is true if the BTF originated with the kernel and not
	// userspace.
	IsKernel bool

	// Size of the raw BTF in bytes.
	size uint32
}

func newHandleInfoFromFD(fd *sys.FD) (*HandleInfo, error) {
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

	return &HandleInfo{
		ID:       btfInfo.Id,
		Name:     unix.ByteSliceToString(nameBuffer),
		IsKernel: btfInfo.KernelBtf != 0,
		size:     btfSize,
	}, nil
}

// IsModule returns true if the BTF is for the kernel itself.
func (i *HandleInfo) IsVmlinux() bool {
	return i.IsKernel && i.Name == "vmlinux"
}

// IsModule returns true if the BTF is for a kernel module.
func (i *HandleInfo) IsModule() bool {
	return i.IsKernel && i.Name != "vmlinux"
}
