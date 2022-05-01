//go:build !386 && !amd64 && !amd64p32 && !arm && !arm64 && !mipsle && !mips64le && !mips64p32le && !ppc64le && !riscv64 && !armbe && !arm64be && !mips && !mips64 && !mips64p32 && !ppc64 && !s390 && !s390x && !sparc && !sparc64
// +build !386,!amd64,!amd64p32,!arm,!arm64,!mipsle,!mips64le,!mips64p32le,!ppc64le,!riscv64,!armbe,!arm64be,!mips,!mips64,!mips64p32,!ppc64,!s390,!s390x,!sparc,!sparc64

package internal

import (
	"encoding/binary"
	"unsafe"
)

// NativeEndian is set to either binary.BigEndian or binary.LittleEndian,
// depending on the host's endianness.
var NativeEndian binary.ByteOrder

// ClangEndian is set to either "el" or "eb" depending on the host's endianness.
var ClangEndian string

func init() {
	if isBigEndian() {
		NativeEndian = binary.BigEndian
		ClangEndian = "eb"
	} else {
		NativeEndian = binary.LittleEndian
		ClangEndian = "el"
	}
}

func isBigEndian() (ret bool) {
	i := int(0x1)
	bs := (*[int(unsafe.Sizeof(i))]byte)(unsafe.Pointer(&i))
	return bs[0] == 0
}
