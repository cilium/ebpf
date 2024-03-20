package internal

import (
	"encoding/binary"

	"golang.org/x/sys/cpu"
)

// IsNativeEndian returns true if order matches the native endianness of the host.
func IsNativeEndian(order binary.ByteOrder) bool {
	if order == binary.NativeEndian {
		return true
	}

	if !cpu.IsBigEndian {
		return order == binary.LittleEndian
	}

	return order == binary.BigEndian
}

// ByteOrderEqual returns true if the two byte orders are semantically identical.
//
// For example, on a little endian system NativeEndian and LittleEndian are
// considered identical.
func ByteOrderEqual(a, b binary.ByteOrder) bool {
	a = normaliseByteOrder(a)
	b = normaliseByteOrder(b)
	return a == b
}

func normaliseByteOrder(order binary.ByteOrder) binary.ByteOrder {
	if order != binary.NativeEndian {
		return order
	}

	if !cpu.IsBigEndian {
		return binary.LittleEndian
	}

	return binary.BigEndian
}
