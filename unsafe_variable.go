package ebpf

import (
	"unsafe"
)

//go:linkname unsafeVariablePointer
func unsafeVariablePointer(v *Variable) (unsafe.Pointer, error) {
	if v.mm == nil {
		return nil, errNoDirectVariableAccess(v)
	}

	b, err := v.mm.sliceAt(v.offset, v.size)
	if err != nil {
		return nil, err
	}

	return unsafe.Pointer(&b[0]), nil
}
