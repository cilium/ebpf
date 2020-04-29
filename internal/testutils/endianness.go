package testutils

import (
	"unsafe"
)

func GetHostEndianness() string {
	test := uint16(0x0740)
	if *(*uint8)(unsafe.Pointer(&test)) == 0x40 {
		return "el"
	} else {
		return "eb"
	}
}
