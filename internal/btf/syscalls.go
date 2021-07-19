package btf

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

type bpfBTFInfo struct {
	btf       internal.Pointer
	btfSize   uint32
	id        uint32
	name      internal.Pointer
	nameLen   uint32
	kernelBTF uint32
}

func bpfGetBTFInfoByFD(fd *internal.FD, btf, name []byte) (*bpfBTFInfo, error) {
	info := bpfBTFInfo{
		btf:     internal.NewSlicePointer(btf),
		btfSize: uint32(len(btf)),
		name:    internal.NewSlicePointer(name),
		nameLen: uint32(len(name)),
	}
	if err := internal.BPFObjGetInfoByFD(fd, unsafe.Pointer(&info), unsafe.Sizeof(info)); err != nil {
		return nil, fmt.Errorf("can't get program info: %w", err)
	}

	return &info, nil
}

// Everything below here is redefined to prevent an import cycle
type bpfGetFDByIDAttr struct {
	id   uint32
	next uint32
}

func wrapObjError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, unix.ENOENT) {
		return fmt.Errorf("%w", ErrNotExist)
	}

	return errors.New(err.Error())
}

func bpfObjGetFDByID(cmd internal.BPFCmd, id uint32) (*internal.FD, error) {
	attr := bpfGetFDByIDAttr{
		id: id,
	}
	ptr, err := internal.BPF(cmd, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return internal.NewFD(uint32(ptr)), wrapObjError(err)
}

var ErrNotExist = errors.New("requested object does not exist")
