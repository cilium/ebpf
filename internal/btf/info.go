package btf

import (
	"bytes"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
)

// info describes a BTF object.
type info struct {
	BTF *Spec
	ID  ID
	// Name is an identifying name for the BTF, currently only used by the
	// kernel.
	Name string
	// KernelBTF is true if the BTf originated with the kernel and not
	// userspace.
	KernelBTF bool
}

func newInfoFromFd(fd *sys.FD) (*info, error) {
	// We invoke the syscall once with a empty BTF and name buffers to get size
	// information to allocate buffers. Then we invoke it a second time with
	// buffers to receive the data.
	bpfInfo, err := bpfGetBTFInfoByFD(fd, nil, nil)
	if err != nil {
		return nil, err
	}

	btfBuffer := make([]byte, bpfInfo.BtfSize)
	nameBuffer := make([]byte, bpfInfo.NameLen)
	bpfInfo, err = bpfGetBTFInfoByFD(fd, btfBuffer, nameBuffer)
	if err != nil {
		return nil, err
	}

	spec, err := loadRawSpec(bytes.NewReader(btfBuffer), internal.NativeEndian, nil, nil)
	if err != nil {
		return nil, err
	}

	return &info{
		BTF:       spec,
		ID:        ID(bpfInfo.Id),
		Name:      internal.CString(nameBuffer),
		KernelBTF: bpfInfo.KernelBtf != 0,
	}, nil
}
