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

	f, err := os.Open(opts.Path)
	if err != nil {
		return nil, fmt.Errorf("can't open file: %s", err)
	}
	defer f.Close()

	// query the number of programs to allocate correct slice size
	attr := sys.ProgQueryAttr{
		TargetFd:    uint32(f.Fd()),
		AttachType:  sys.AttachType(opts.AttachType),
		AttachFlags: uint32(opts.AttachFlags),
		QueryFlags:  opts.QueryFlags,
		ProgIds:     sys.NewPointer(unsafe.Pointer(nil)),
		ProgCount:   uint32(0),
	}
	err = sys.ProgQuery(&attr)
	if err != nil {
		return nil, fmt.Errorf("can't query program count: %w", err)
	}

	// return empty slice if no progs are attached
	if attr.ProgCount == 0 {
		return []ebpf.ProgramID{}, nil
	}

	// we have at least one prog, so we query again
	progIds := make([]ebpf.ProgramID, attr.ProgCount)
	attr = sys.ProgQueryAttr{
		TargetFd:    uint32(f.Fd()),
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
