//go:build !windows

package link

import (
	"fmt"
	"io"
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
}

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

	switch {
	default:
		// Also covers iterators without parameters, with a nil opts.Map.
		return attachIterMap(&attr, opts.Map)
	}
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
