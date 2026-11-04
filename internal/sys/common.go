package sys

import "unsafe"

// MapCreateWithCommon creates a map with common syscall attributes.
func MapCreateWithCommon(attr *MapCreateAttr, common *CommonAttr) (*FD, error) {
	fd, err := BPFWithCommonAttrs(BPF_MAP_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr), common)
	if err != nil {
		return nil, err
	}
	return NewFD(int(fd))
}
