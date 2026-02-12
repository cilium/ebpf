package testutils

import (
	"github.com/cilium/ebpf/internal/sys"
)

var TOKEN_SUBTEST = `TOKEN_SUBTEST`

type Delegated struct {
	Cmds        []sys.Cmd
	Maps        []sys.MapType
	Progs       []sys.ProgType
	AttachTypes []sys.AttachType
}
