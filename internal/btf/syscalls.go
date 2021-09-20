package btf

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/internal/sys"
)

func bpfGetBTFInfoByFD(fd *sys.FD, btf, name []byte) (*sys.BtfInfo, error) {
	info := sys.BtfInfo{
		Btf:     sys.NewSlicePointer(btf),
		BtfSize: uint32(len(btf)),
		Name:    sys.NewSlicePointer(name),
		NameLen: uint32(len(name)),
	}
	if err := sys.ObjGetInfoByFD(fd, unsafe.Pointer(&info), unsafe.Sizeof(info)); err != nil {
		return nil, fmt.Errorf("can't get program info: %w", err)
	}

	return &info, nil
}
