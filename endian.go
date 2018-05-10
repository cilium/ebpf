package ebpf

import (
	"encoding/binary"
	"unsafe"
)

var nativeEndian binary.ByteOrder

func init() {
	if isBigEndian() {
		nativeEndian = binary.BigEndian
	} else {
		nativeEndian = binary.LittleEndian
	}
}

func isBigEndian() (ret bool) {
	i := int(0x1)
	bs := (*[int(unsafe.Sizeof(i))]byte)(unsafe.Pointer(&i))
	return bs[0] == 0
}
