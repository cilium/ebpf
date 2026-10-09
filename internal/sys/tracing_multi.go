package sys

import (
	"structs"
	"unsafe"
)

type LinkCreateTracingMultiAttr struct {
	_          structs.HostLayout
	ProgFd     uint32
	TargetFd   uint32
	AttachType AttachType
	Flags      uint32
	Ids        TypedPointer[TypeID]
	Cookies    TypedPointer[uint64]
	Count      uint32
	_          [28]byte
}

func LinkCreateTracingMulti(attr *LinkCreateTracingMultiAttr) (*FD, error) {
	fd, err := BPF(BPF_LINK_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err != nil {
		return nil, err
	}
	return NewFD(int(fd))
}
