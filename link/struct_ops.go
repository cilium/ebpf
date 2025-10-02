package link

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/sys"
)

type structOpsLink struct {
	*RawLink
	m *ebpf.Map
}

// AttachStructOps links a StructOps map
func AttachStructOps(m *ebpf.Map) (*structOpsLink, error) {
	if m == nil {
		return nil, fmt.Errorf("attach StructOps: map cannot be nil: %w", errInvalidInput)
	}

	if t := m.Type(); t != ebpf.StructOpsMap {
		return nil, fmt.Errorf("attach StrcutOps: invalid map type %s, expected struct_ops: %w", t, errInvalidInput)
	}

	mapFD, err := sys.NewFD(m.FD())
	if err != nil {
		return nil, fmt.Errorf("attach StructOps: %w", err)
	}

	if (int(m.Flags()) & sys.BPF_F_LINK) != sys.BPF_F_LINK {
		return &structOpsLink{&RawLink{mapFD, ""}, m}, nil
	}

	fd, err := sys.LinkCreate(&sys.LinkCreateAttr{
		ProgFd:     uint32(m.FD()),
		AttachType: sys.AttachType(ebpf.AttachStructOps),
		TargetFd:   0,
	})
	if err != nil {
		return nil, fmt.Errorf("attach StructOps: create link: %w", err)
	}

	rawLink := &RawLink{fd, ""}
	return &structOpsLink{rawLink, nil}, nil
}

// DetachStructOps detaches a StructOps
func (l *structOpsLink) DetachStructOps() error {
	if l.m != nil {
		// delete kern_vdata directly when it's without real link
		return l.m.Delete(uint32(0))
	}
	return l.Close()
}
