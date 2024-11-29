package link

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/sys"
)

// AttachStructOps attaches a struct_ops map to the kernel. This causes all programs
// contained in the map's value to be attached as well. This only works for map
// which were loaded with the `BPF_F_LINK` flag. Maps loaded without this flag
// will auto-attach as soon as its map value is updated.
// The location in the kernel where the struct_ops map is attached to is determined
// by the `Value` type of the map when it was loaded.
func AttachStructOps(m *ebpf.Map) (Link, error) {
	if m.Type() != ebpf.StructOpsMap {
		return nil, fmt.Errorf("map is not a struct_ops map")
	}

	if m.Flags() != sys.BPF_F_LINK {
		return nil, fmt.Errorf("struct_ops map was not loaded with the `BPF_F_LINK` flag")
	}

	attr := sys.LinkCreateAttr{
		// We assign the FD of the map to the ProgFd field, this is not a mistake.
		// The kernel defines this field as a union of program FD or map FD, but this
		// is not reflected in the Go struct.
		ProgFd:     uint32(m.FD()),
		AttachType: sys.BPF_STRUCT_OPS,
	}

	fd, err := sys.LinkCreate(&attr)
	if err != nil {
		return nil, fmt.Errorf("attach struct_ops link: %w", err)
	}

	return &RawLink{fd: fd}, nil
}
