package link

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
)

var _ Link = (*BTFIDLink)(nil)

// BTFIDLink is a program attached to a btf_id.
type BTFIDLink struct {
	RawLink
}

// Update implements the Link interface.
func (*BTFIDLink) Update(_ *ebpf.Program) error {
	return fmt.Errorf("can't update fentry/fexit/fmod_ret/rp_raw/lsm: %w", ErrNotSupported)
}

// attachBTFID links all BPF program types (Tracing/LSM) that they attach to a btf_id.
func attachBTFID(program *ebpf.Program) (Link, error) {
	if t := program.Type(); t != ebpf.Tracing && t != ebpf.LSM {
		return nil, fmt.Errorf("invalid program type %s, expected Tracing/LSM", t)
	}

	if program.FD() < 0 {
		return nil, fmt.Errorf("invalid program %w", internal.ErrClosedFd)
	}

	fd, err := bpfRawTracepointOpen(&bpfRawTracepointOpenAttr{
		fd: uint32(program.FD()),
	})
	if err != nil {
		return nil, err
	}

	return &BTFIDLink{RawLink: RawLink{fd: fd}}, nil
}

// AttachTrace links a tracing (fentry/fexit/fmod_ret) BPF program or
// a BTF-powered raw tracepoint (tp_btf) BPF Program to a BPF hook defined
// in kernel modules.
//
// Requires at least Linux 5.5.
func AttachTrace(program *ebpf.Program) (Link, error) {
	return attachBTFID(program)
}

// AttachLSM links a Linux security module (LSM) BPF Program to a BPF
// hook defined in kernel modules.
//
// Requires at least Linux 5.7.
func AttachLSM(program *ebpf.Program) (Link, error) {
	return attachBTFID(program)
}

// LoadPinnedTrace loads a tracing/LSM link from a bpffs.
func LoadPinnedTrace(fileName string, opts *ebpf.LoadPinOptions) (*BTFIDLink, error) {
	link, err := LoadPinnedRawLink(fileName, TracingType, opts)
	if err != nil {
		return nil, err
	}

	return &BTFIDLink{*link}, err
}

// LoadPinnedTraceRawTP loads a tp_btf link from a bpffs.
func LoadPinnedTraceRawTP(fileName string, opts *ebpf.LoadPinOptions) (*BTFIDLink, error) {
	link, err := LoadPinnedRawLink(fileName, RawTracepointType, opts)
	if err != nil {
		return nil, err
	}

	return &BTFIDLink{*link}, err
}
