package link

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/sys"
)

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

	raw := RawLink{fd: fd}
	info, err := raw.Info()
	if err != nil {
		raw.Close()
		return nil, err
	}

	if info.Type == RawTracepointType {
		// Sadness upon sadness: a Tracing program with AttachRawTp returns
		// a raw_tracepoint link. Other types return a tracing link.
		return &rawTracepoint{raw}, nil
	}

	return &tracing{RawLink: RawLink{fd: fd}}, nil
}

// AttachTrace links a tracing (fentry/fexit/fmod_ret) BPF program or
// a BTF-powered raw tracepoint (tp_btf) BPF Program to a BPF hook defined
// in kernel modules.
func AttachTrace(opts TraceOptions) (Link, error) {
	return attachBTFID(opts.Program)
}

// AttachLSM links a Linux security module (LSM) BPF Program to a BPF
// hook defined in kernel modules.
func AttachLSM(opts LSMOptions) (Link, error) {
	return attachBTFID(opts.Program)
}

// LoadPinnedTrace loads a tracing/LSM link from a bpffs.
func LoadPinnedTrace(fileName string, opts *ebpf.LoadPinOptions) (Link, error) {
	link, err := LoadPinnedRawLink(fileName, TracingType, opts)
	if err != nil {
		return nil, err
	}

	return &tracing{*link}, err
}
