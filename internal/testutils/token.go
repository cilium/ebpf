package testutils

import (
	"fmt"
	"math"

	"github.com/cilium/ebpf/internal/sys"
)

var TOKEN_SUBTEST = `TOKEN_SUBTEST`

type Delegated struct {
	Cmds        []sys.Cmd
	Maps        []sys.MapType
	Progs       []sys.ProgType
	AttachTypes []sys.AttachType
}

const DelegateAny uint32 = math.MaxUint32

func delegateString[T ~uint32](enums []T) string {
	var sum uint64
	for _, v := range enums {
		if uint32(v) == DelegateAny {
			return "any"
		}

		sum |= uint64(1) << v
	}

	return fmt.Sprintf("0x%x", sum)
}
