//go:build !windows

package link

import (
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

	// Map specifies the target map for bpf_map_elem and sockmap iterators. It
	// may be nil. Mutually exclusive with Cgroup.
	Map *ebpf.Map

	// Cgroup specifies where a cgroup iterator starts and in which order it
	// walks the cgroup hierarchy. Required for cgroup iterators. Mutually
	// exclusive with Map. Available on Linux 6.1 and later.
	Cgroup *CgroupIterOptions
}

// CgroupIterOptions configures a cgroup iterator.
type CgroupIterOptions struct {
	// Order in which the iterator walks the cgroup hierarchy. Required.
	Order CgroupIterOrder

	// Path to the cgroup directory the walk starts from. If both Path and ID
	// are empty, the walk starts at the root of the cgroupv2 hierarchy.
	// Mutually exclusive with ID.
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
	CgroupIterSelfOnly = CgroupIterOrder(sys.BPF_CGROUP_ITER_SELF_ONLY)

	// CgroupIterDescendantsPre visits the starting cgroup and its descendants,
	// every parent before its children.
	CgroupIterDescendantsPre = CgroupIterOrder(sys.BPF_CGROUP_ITER_DESCENDANTS_PRE)

	// CgroupIterDescendantsPost visits the starting cgroup and its descendants,
	// every parent after its children.
	CgroupIterDescendantsPost = CgroupIterOrder(sys.BPF_CGROUP_ITER_DESCENDANTS_POST)

	// CgroupIterAncestorsUp visits the starting cgroup and its ancestors, up to
	// the root.
	CgroupIterAncestorsUp = CgroupIterOrder(sys.BPF_CGROUP_ITER_ANCESTORS_UP)

	// CgroupIterChildren visits the immediate children of the starting cgroup
	// only, not the parent. Requires Linux 7.0 or later.
	CgroupIterChildren = CgroupIterOrder(sys.BPF_CGROUP_ITER_CHILDREN)
)

// AttachIter attaches a BPF seq_file iterator.
func AttachIter(opts IterOptions) (*Iter, error) {
	if err := validateIterOptions(opts); err != nil {
		return nil, fmt.Errorf("iter options: %w", err)
	}

	progFd := opts.Program.FD()
	if progFd < 0 {
		return nil, fmt.Errorf("invalid program: %s", sys.ErrClosedFd)
	}

	attr := sys.LinkCreateIterAttr{
		ProgFd:     uint32(progFd),
		AttachType: sys.AttachType(ebpf.AttachTraceIter),
	}

	switch {
	case opts.Cgroup != nil:
		return attachIterCgroup(&attr, opts.Cgroup)
	default:
		// Also covers iterators without parameters, with a nil opts.Map.
		return attachIterMap(&attr, opts.Map)
	}
}

// validateIterOptions checks opts for missing and mutually exclusive fields.
func validateIterOptions(opts IterOptions) error {
	if opts.Program == nil {
		return fmt.Errorf("program cannot be nil: %w", errInvalidInput)
	}

	set := 0
	for _, ok := range []bool{opts.Map != nil, opts.Cgroup != nil} {
		if ok {
			set++
		}
	}
	if set > 1 {
		return fmt.Errorf("map and cgroup are mutually exclusive: %w", errInvalidInput)
	}

	if opts.Cgroup != nil {
		if opts.Cgroup.Order == 0 {
			return fmt.Errorf("cgroup iteration order must be specified: %w", errInvalidInput)
		}

		if opts.Cgroup.Path != "" && opts.Cgroup.ID != 0 {
			return fmt.Errorf("cgroup path and ID are mutually exclusive: %w", errInvalidInput)
		}
	}

	return nil
}

// attachIterMap attaches an iterator over the elements of m.
//
// Also used by default for iterators without a parameter.
func attachIterMap(attr *sys.LinkCreateIterAttr, m *ebpf.Map) (*Iter, error) {
	var info sys.IterLinkInfoMap
	if m != nil {
		mapFd := m.FD()
		if mapFd < 0 {
			return nil, fmt.Errorf("invalid map: %w", sys.ErrClosedFd)
		}
		info.MapFd = uint32(mapFd)
	}

	attr.IterInfo = sys.UnsafePointer(unsafe.Pointer(&info))
	attr.IterInfoLen = uint32(unsafe.Sizeof(info))

	return createIter(attr)
}

// attachIterCgroup attaches a cgroup iterator.
func attachIterCgroup(attr *sys.LinkCreateIterAttr, opts *CgroupIterOptions) (*Iter, error) {
	info := sys.IterLinkInfoCgroup{
		Order:    sys.CgroupIterOrder(opts.Order),
		CgroupId: opts.ID,
	}

	if opts.Path != "" {
		cgroup, err := os.Open(opts.Path)
		if err != nil {
			return nil, fmt.Errorf("can't open cgroup: %w", err)
		}
		// fd must outlive link creation.
		defer cgroup.Close()

		info.CgroupFd = uint32(cgroup.Fd())
	}

	attr.IterInfo = sys.UnsafePointer(unsafe.Pointer(&info))
	attr.IterInfoLen = uint32(unsafe.Sizeof(info))

	return createIter(attr)
}

func createIter(attr *sys.LinkCreateIterAttr) (*Iter, error) {
	fd, err := sys.LinkCreateIter(attr)
	if err != nil {
		if haveFeatErr := haveBPFLink(); haveFeatErr != nil {
			return nil, haveFeatErr
		}
		return nil, fmt.Errorf("can't link iterator: %w", err)
	}

	return &Iter{RawLink{fd, ""}}, nil
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
