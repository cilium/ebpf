//go:build !windows

package link

import (
	"errors"
	"fmt"
	"io"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/sys"
)

type IterOptions struct {
	// Program must be of type Tracing with attach type
	// AttachTraceIter. The kind of iterator to attach to is
	// determined at load time via the AttachTo field.
	//
	// AttachTo requires the kernel to include BTF of itself,
	// and it to be compiled with a recent pahole (>= 1.16).
	Program *ebpf.Program

	// Map specifies the target map for bpf_map_elem and sockmap iterators.
	// It may be nil.
	Map *ebpf.Map

	// Cgroup specifies where a cgroup iterator starts and in which order it
	// walks the cgroup hierarchy. It is required for cgroup iterators and
	// can't be combined with Map.
	Cgroup *CgroupIterOptions
}

// CgroupIterOptions configures a cgroup iterator.
type CgroupIterOptions struct {
	// Order in which the iterator walks the cgroup hierarchy. Required.
	Order CgroupIterOrder

	// Path to the cgroup directory the walk starts from. If both Path and ID
	// are empty, the walk starts at the root of the cgroupv2 hierarchy.
	Path string

	// ID of the cgroup the walk starts from, as returned by
	// bpf_get_current_cgroup_id(). Mutually exclusive with Path.
	ID uint64
}

// CgroupIterOrder is the order in which a cgroup iterator walks the cgroup
// hierarchy. It mirrors enum bpf_cgroup_iter_order.
type CgroupIterOrder uint32

const (
	// CgroupIterSelfOnly visits the starting cgroup only.
	CgroupIterSelfOnly CgroupIterOrder = 1
	// CgroupIterDescendantsPre visits the starting cgroup and its
	// descendants, every parent before its children.
	CgroupIterDescendantsPre CgroupIterOrder = 2
	// CgroupIterDescendantsPost visits the starting cgroup and its
	// descendants, every parent after its children.
	CgroupIterDescendantsPost CgroupIterOrder = 3
	// CgroupIterAncestorsUp visits the starting cgroup and its ancestors, up
	// to the root.
	CgroupIterAncestorsUp CgroupIterOrder = 4
)

// AttachIter attaches a BPF seq_file iterator.
func AttachIter(opts IterOptions) (*Iter, error) {
	progFd := opts.Program.FD()
	if progFd < 0 {
		return nil, fmt.Errorf("invalid program: %s", sys.ErrClosedFd)
	}

	attr := sys.LinkCreateIterAttr{
		ProgFd:     uint32(progFd),
		AttachType: sys.AttachType(ebpf.AttachTraceIter),
	}

	if opts.Cgroup != nil {
		if opts.Map != nil {
			return nil, errors.New("options Map and Cgroup are mutually exclusive")
		}

		info := bpfIterLinkInfoCgroup{
			order:     uint32(opts.Cgroup.Order),
			cgroup_id: opts.Cgroup.ID,
		}
		if opts.Cgroup.Path != "" {
			// The kernel takes its own reference to the cgroup, so the
			// directory only needs to stay open until the link exists.
			cgroup, err := os.Open(opts.Cgroup.Path)
			if err != nil {
				return nil, fmt.Errorf("can't open cgroup: %w", err)
			}
			defer cgroup.Close()
			info.cgroup_fd = uint32(cgroup.Fd())
		}

		attr.IterInfo = sys.UnsafePointer(unsafe.Pointer(&info))
		attr.IterInfoLen = uint32(unsafe.Sizeof(info))
	} else {
		var info bpfIterLinkInfoMap
		if opts.Map != nil {
			mapFd := opts.Map.FD()
			if mapFd < 0 {
				return nil, fmt.Errorf("invalid map: %w", sys.ErrClosedFd)
			}
			info.map_fd = uint32(mapFd)
		}

		attr.IterInfo = sys.UnsafePointer(unsafe.Pointer(&info))
		attr.IterInfoLen = uint32(unsafe.Sizeof(info))
	}

	fd, err := sys.LinkCreateIter(&attr)
	if err != nil {
		if haveFeatErr := haveBPFLink(); haveFeatErr != nil {
			return nil, haveFeatErr
		}
		return nil, fmt.Errorf("can't link iterator: %w", err)
	}

	return &Iter{RawLink{fd, ""}}, err
}

// Iter represents an attached bpf_iter.
type Iter struct {
	RawLink
}

func (it *Iter) Info() (*Info, error) {
	var info sys.IterLinkInfo
	name, err := queryInfoWithString(it.fd, &info, &info.TargetName, &info.TargetNameLen)
	if err != nil {
		return nil, err
	}
	return &Info{
		info.Type,
		info.Id,
		ebpf.ProgramID(info.ProgId),
		&IterInfo{TargetName: name},
	}, nil
}

// Open creates a new instance of the iterator.
//
// Reading from the returned reader triggers the BPF program.
func (it *Iter) Open() (io.ReadCloser, error) {
	attr := &sys.IterCreateAttr{
		LinkFd: it.fd.Uint(),
	}

	fd, err := sys.IterCreate(attr)
	if err != nil {
		return nil, fmt.Errorf("can't create iterator: %w", err)
	}

	return fd.File("bpf_iter")
}

// union bpf_iter_link_info.map
type bpfIterLinkInfoMap struct {
	map_fd uint32
}

// union bpf_iter_link_info.cgroup
type bpfIterLinkInfoCgroup struct {
	order     uint32
	cgroup_fd uint32
	cgroup_id uint64
}
