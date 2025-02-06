package internal

import (
	"encoding/binary"

	"golang.org/x/sys/cpu"
)

var NativeEndian = binary.NativeEndian

func EqualByteOrder(bo1, bo2 binary.ByteOrder) bool {
	return NormalizeByteOrder(bo1) == NormalizeByteOrder(bo2)
}

// NormalizeByteOrder replaces binary.NativeEndian with the underlying
// byte order (BigEndian or LittleEndian).
func NormalizeByteOrder(bo binary.ByteOrder) binary.ByteOrder {
	if bo != binary.NativeEndian {
		return bo
	}
	if cpu.IsBigEndian {
		return binary.BigEndian
	}
	return binary.LittleEndian
}
