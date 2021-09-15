package btf

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/internal/sys"
)

type bpfBTFInfo struct {
	btf       sys.Pointer
	btfSize   uint32
	id        uint32
	name      sys.Pointer
	nameLen   uint32
	kernelBTF uint32
}

func bpfGetBTFInfoByFD(fd *sys.FD, btf, name []byte) (*bpfBTFInfo, error) {
	info := bpfBTFInfo{
		btf:     sys.NewSlicePointer(btf),
		btfSize: uint32(len(btf)),
		name:    sys.NewSlicePointer(name),
		nameLen: uint32(len(name)),
	}
	if err := sys.BPFObjGetInfoByFD(fd, unsafe.Pointer(&info), unsafe.Sizeof(info)); err != nil {
		return nil, fmt.Errorf("can't get program info: %w", err)
	}

	return &info, nil
}
