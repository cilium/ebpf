package link

import (
	"fmt"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/efw"
	"github.com/cilium/ebpf/internal/sys"
)

func AttachRawLink(opts RawLinkOptions) (*RawLink, error) {
	if opts.Target != 0 || opts.BTF != 0 || opts.Flags != 0 {
		return nil, fmt.Errorf("specified option(s) %w", internal.ErrNotSupportedOnOS)
	}

	p, attachType := opts.Attach.Decode()
	if p != internal.WindowsPlatform {
		return nil, fmt.Errorf("attach type %s: %w", opts.Attach, internal.ErrNotSupportedOnOS)
	}

	attachTypeGUID, err := efw.EbpfGetEbpfAttachType(attachType)
	if err != nil {
		return nil, fmt.Errorf("get attach type: %w", err)
	}

	raw, err := efw.EbpfProgramAttachFds(opts.Program.FD(), attachTypeGUID, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("attach link: %w", err)
	}

	fd, err := sys.NewFD(int(raw))
	if err != nil {
		return nil, err
	}

	return &RawLink{fd: fd}, nil
}

func wrapRawLink(raw *RawLink) (Link, error) {
	return raw, nil
}
