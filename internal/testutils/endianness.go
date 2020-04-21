package testutils

import (
        "encoding/binary"

	"github.com/cilium/ebpf/internal"
)

func GetHostEndianness() string {
	if internal.NativeEndian == binary.LittleEndian {
		return "el"
	} else {
		return "eb"
	}
}
