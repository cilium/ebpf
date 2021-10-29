package link

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/sys"
)

var _ Link = (*btfIDLink)(nil)

// btfIDLink is a program attached to a btf_id.
type btfIDLink struct {
	RawLink
}

type TraceOptions struct {
	// Program must be of type Tracing with attach type
	// AttachTraceFEntry/AttachTraceFExit/AttachModifyReturn or
	// AttachTraceRawTp.
	Program *ebpf.Program
}
type LSMOptions struct {
	// Program must be of type LSM with attach type
	// AttachLSMMac.
	Program *ebpf.Program
}

// Update implements the Link interface.
func (*btfIDLink) Update(_ *ebpf.Program) error {
	return fmt.Errorf("can't update fentry/fexit/fmod_ret/tp_raw/lsm: %w", ErrNotSupported)
}

// attachBTFID links all BPF program types (Tracing/LSM) that they attach to a btf_id.
func attachBTFID(program *ebpf.Program) (Link, error) {
	if t := program.Type(); t != ebpf.Tracing && t != ebpf.LSM {
		return nil, fmt.Errorf("invalid program type %s, expected Tracing/LSM", t)
	}

	if program.FD() < 0 {
		return nil, fmt.Errorf("invalid program %w", sys.ErrClosedFd)
	}

	fd, err := sys.RawTracepointOpen(&sys.RawTracepointOpenAttr{
		ProgFd: uint32(program.FD()),
	})
	if err != nil {
		return nil, err
	}

	return &btfIDLink{RawLink: RawLink{fd: fd}}, nil
}

// AttachTrace links a tracing (fentry/fexit/fmod_ret) BPF program or
// a BTF-powered raw tracepoint (tp_btf) BPF Program to a BPF hook defined
// in kernel modules.
//
// Requires at least Linux 5.11.
func AttachTrace(opts TraceOptions) (Link, error) {
	return attachBTFID(opts.Program)
}

// AttachLSM links a Linux security module (LSM) BPF Program to a BPF
// hook defined in kernel modules.
//
// Requires at least Linux 5.11.
func AttachLSM(opts LSMOptions) (Link, error) {
	return attachBTFID(opts.Program)
}

// LoadPinnedTrace loads a tracing/LSM link from a bpffs.
func LoadPinnedTrace(fileName string, opts *ebpf.LoadPinOptions) (Link, error) {
	link, err := LoadPinnedRawLink(fileName, TracingType, opts)
	if err != nil {
		return nil, err
	}

	return &btfIDLink{*link}, err
}

// LoadPinnedTraceRawTP loads a tp_btf link from a bpffs.
func LoadPinnedTraceRawTP(fileName string, opts *ebpf.LoadPinOptions) (Link, error) {
	link, err := LoadPinnedRawLink(fileName, RawTracepointType, opts)
	if err != nil {
		return nil, err
	}

	return &btfIDLink{*link}, err
}
