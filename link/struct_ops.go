package link

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/sys"
)

type structOpsLink struct {
	*RawLink
}

// AttachStructOps attaches a struct_ops map (created from a ".struct_ops.link"
// section) to its kernel subsystem via a BPF link.
func AttachStructOps(m *ebpf.Map) (Link, error) {
	if m == nil {
		return nil, fmt.Errorf("map cannot be nil")
	}

	if t := m.Type(); t != ebpf.StructOpsMap {
		return nil, fmt.Errorf("invalid map type %s, expected struct_ops", t)
	}

	mapFD := m.FD()
	if mapFD <= 0 {
		return nil, fmt.Errorf("invalid map: %s (was it created?)", sys.ErrClosedFd)
	}

	// ".struct_ops.link" requires the map to be created with BPF_F_LINK.
	if (int(m.Flags()) & sys.BPF_F_LINK) != sys.BPF_F_LINK {
		return nil, fmt.Errorf("map is missing BPF_F_LINK flag: %w", ErrNotSupported)
	}

	fd, err := sys.LinkCreate(&sys.LinkCreateAttr{
		// struct_ops expects target_fd = map FD
		ProgFd:     uint32(mapFD),
		AttachType: sys.AttachType(ebpf.AttachStructOps),
		TargetFd:   0,
	})
	if err != nil {
		return nil, fmt.Errorf("attach StructOps: create link: %w", err)
	}

	return &structOpsLink{&RawLink{fd: fd}}, nil
}
