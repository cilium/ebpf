package btf

import (
	"bytes"

	"github.com/cilium/ebpf/internal"
)

type BTFInfo struct {
	BTF       *Spec
	id        TypeID
	Name      string
	KernelBTF bool
}

func newBTFInfoFromFd(fd *internal.FD) (*BTFInfo, error) {
	// We invoke the syscall once with a empty BTF and name buffers to get size
	// information to allocate buffers. Then we invoke it a second time with
	// buffers to receive the data.
	info, err := bpfGetBTFInfoByFD(fd, nil, nil)
	if err != nil {
		return nil, err
	}

	btfBuffer := make([]byte, info.btfSize)
	nameBuffer := make([]byte, info.nameLen)
	info, err = bpfGetBTFInfoByFD(fd, btfBuffer, nameBuffer)
	if err != nil {
		return nil, err
	}

	spec, err := loadNakedSpec(bytes.NewReader(btfBuffer), internal.NativeEndian, nil, nil)
	if err != nil {
		return nil, err
	}

	return &BTFInfo{
		BTF:       spec,
		id:        TypeID(info.id),
		Name:      internal.CString(nameBuffer),
		KernelBTF: info.kernelBTF != 0,
	}, nil
}
