package raw_tracepoints

import (
	"golang.org/x/xerrors"

	"github.com/cilium/ebpf/internal"
)

// Attach a Program fd to a raw tracepoint.
//
// Requires at least Linux 4.17.
func AttachFD(fd int, tpName string) error {
	if fd < 0 {
		return xerrors.New("invalid program fd")
	}

	attr := bpfRawTracepointOpenAttr{
		name: internal.NewStringPointer(tpName),
		fd:   uint32(fd),
	}

	return bpfRawTracepointOpen(&attr)
}
