//go:build !windows

package link

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

// TracingMultiOptions control attaching a tracing program to multiple functions.
type TracingMultiOptions struct {
	// Program must be of type Tracing with attach type AttachTraceFEntryMulti,
	// AttachTraceFExitMulti or AttachTraceFSessionMulti.
	Program *ebpf.Program

	// AttachType must match the attach type of Program. It must be one of:
	//  - AttachTraceFEntryMulti
	//  - AttachTraceFExitMulti
	//  - AttachTraceFSessionMulti
	AttachType ebpf.AttachType

	// BTFIDs is the set of kernel function BTF IDs to attach to.
	BTFIDs []btf.TypeID

	// Cookies specifies arbitrary values that can be fetched from an eBPF
	// program via bpf_get_attach_cookie().
	//
	// If set, its length must be equal to the length of BTFIDs. Each cookie is
	// assigned to the BTF ID at the corresponding slice index.
	Cookies []uint64
}

// AttachTracingMulti links a tracing BPF program to multiple kernel function
// BTF IDs.
//
// Requires at least Linux 7.2.
func AttachTracingMulti(opts TracingMultiOptions) (Link, error) {
	if opts.Program == nil {
		return nil, fmt.Errorf("program cannot be nil: %w", errInvalidInput)
	}
	if t := opts.Program.Type(); t != ebpf.Tracing {
		return nil, fmt.Errorf("invalid program type %s, expected Tracing: %w", t, errInvalidInput)
	}
	if opts.Program.FD() < 0 {
		return nil, fmt.Errorf("invalid program: %w", sys.ErrClosedFd)
	}

	switch opts.AttachType {
	case ebpf.AttachTraceFEntryMulti, ebpf.AttachTraceFExitMulti, ebpf.AttachTraceFSessionMulti:
	default:
		return nil, fmt.Errorf("invalid attach type %s: %w", opts.AttachType, errInvalidInput)
	}

	ids := len(opts.BTFIDs)
	if ids == 0 {
		return nil, fmt.Errorf("field BTFIDs is required: %w", errInvalidInput)
	}
	if cookies := len(opts.Cookies); cookies != 0 && cookies != ids {
		return nil, fmt.Errorf("field Cookies must be exactly BTFIDs in length: %w", errInvalidInput)
	}

	attr := &sys.LinkCreateTracingMultiAttr{
		ProgFd:     uint32(opts.Program.FD()),
		AttachType: sys.AttachType(opts.AttachType),
		Ids:        sys.SlicePointer(opts.BTFIDs),
		Count:      uint32(ids),
	}
	if len(opts.Cookies) != 0 {
		attr.Cookies = sys.SlicePointer(opts.Cookies)
	}

	fd, err := sys.LinkCreateTracingMulti(attr)
	if err == nil {
		return &tracingMulti{RawLink{fd, ""}}, nil
	}

	if featureErr := features.HaveBPFLinkTracingMulti(); featureErr != nil {
		return nil, featureErr
	}
	if errors.Is(err, unix.EINVAL) {
		return nil, fmt.Errorf("%w (invalid BTF ID or program AttachType not %s?)", err, opts.AttachType)
	}

	return nil, fmt.Errorf("create tracing_multi link: %w", err)
}

type tracingMulti struct {
	RawLink
}

var _ Link = (*tracingMulti)(nil)

func (f *tracingMulti) Update(_ *ebpf.Program) error {
	return fmt.Errorf("tracing_multi update: %w", ErrNotSupported)
}
