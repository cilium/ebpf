package testutils

import (
	"github.com/cilium/ebpf/internal/sys"
)

// setupUserNS being set indicates that the child should set up a user namespace
// before continuing with the test. Set by the parent before spawning the child
// process.
const setupUserNS = "SETUP_USERNS"

type Delegated struct {
	Cmds        []sys.Cmd
	Maps        []sys.MapType
	Progs       []sys.ProgType
	AttachTypes []sys.AttachType
}
