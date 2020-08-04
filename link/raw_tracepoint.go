package link

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
)

type RawTracepointOptions struct {
	// Tracepoint name.
	Name string
	// Program must be of type RawTracepoint*
	Program *ebpf.Program
}

// AttachRawTracepoint links a BPF program to a raw_tracepoint.
//
// Requires at least Linux 4.17.
func AttachRawTracepoint(opts RawTracepointOptions) (Link, error) {
	link := progAttachRawTracepoint{tpName: opts.Name}
	if err := link.Update(opts.Program); err != nil {
		return nil, err
	}

	return &link, nil
}

type progAttachRawTracepoint struct {
	tpName string
	fd     *internal.FD
}

var _ Link = (*progAttachRawTracepoint)(nil)

func (rt *progAttachRawTracepoint) isLink() {}

func (rt *progAttachRawTracepoint) Close() error {
	if rt.fd == nil {
		return nil
	}

	return rt.fd.Close()
}

func (rt *progAttachRawTracepoint) Update(prog *ebpf.Program) error {
	if prog.FD() < 0 {
		return fmt.Errorf("invalid program: %w", internal.ErrClosedFd)
	}

	fd, err := bpfRawTracepointOpen(&bpfRawTracepointOpenAttr{
		name: internal.NewStringPointer(rt.tpName),
		fd:   uint32(prog.FD()),
	})
	if err != nil {
		return err
	}

	_ = rt.Close()
	rt.fd = fd
	return err
}

func (rt *progAttachRawTracepoint) Pin(_ string) error {
	return fmt.Errorf("can't pin raw_tracepoint: %w", ErrNotSupported)
}
