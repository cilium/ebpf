package link

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/sys"
)

type QueryOptions struct {
	Path        string
	AttachType  ebpf.AttachType
	AttachFlags ebpf.AttachFlags
	QueryFlags  uint32
}

// QueryPrograms retrieves ProgramIDs associated with the AttachType
// from a given kernel resource, e.g. a cgroup, netns or LIRC2 device.
func QueryPrograms(opts QueryOptions) ([]ebpf.ProgramID, error) {
	if haveProgQuery() != nil {
		return nil, fmt.Errorf("can't query program IDs: %w", ErrNotSupported)
	}

	cgroup, err := os.Open(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("can't open cgroup: %s", err)
	}

	// maybe we want the size to be configurable by the caller?
	progIds := make([]ebpf.ProgramID, 128)
	attr := sys.ProgQueryAttr{
		TargetFd:    uint32(cgroup.Fd()),
		AttachType:  sys.AttachType(opts.AttachType),
		AttachFlags: uint32(opts.AttachFlags),
		QueryFlags:  opts.QueryFlags,
		ProgIds:     sys.NewPointer(unsafe.Pointer(&progIds[0])),
		ProgCount:   uint32(len(progIds)),
	}
	err = sys.ProgQuery(&attr)
	if err != nil {
		return nil, fmt.Errorf("can't query program IDs: %w", err)
	}

	return progIds, nil

}
