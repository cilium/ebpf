package pin

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/link"
)

// Pinner is an interface implemented by all eBPF objects that support pinning
// to a bpf virtual filesystem.
type Pinner interface {
	Pin(string) error
}

// Load retrieves a pinned object from a bpf virtual filesystem. It returns one
// of [ebpf.Map], [ebpf.Program], or [link.Link].
//
// Trying to open anything other than a bpf object is an error.
func Load(path string, opts *ebpf.LoadPinOptions) (Pinner, error) {
	fd, typ, err := sys.ObjGetTyped(&sys.ObjGetAttr{
		Pathname:  sys.NewStringPointer(path),
		FileFlags: opts.Marshal(),
	})
	if err != nil {
		return nil, fmt.Errorf("opening pin %s: %w", path, err)
	}

	switch typ {
	case sys.BPF_TYPE_MAP:
		return ebpf.NewMapFromFD(fd.Disown())
	case sys.BPF_TYPE_PROG:
		return ebpf.NewProgramFromFD(fd.Disown())
	case sys.BPF_TYPE_LINK:
		return link.NewFromFD(fd.Disown())
	}

	return nil, fmt.Errorf("unknown object type %d", typ)
}
