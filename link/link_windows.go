package link

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/efw"
	"github.com/cilium/ebpf/internal/sys"
)

// ebpf_result_t ebpf_program_attach_by_fd(
// fd_t program_fd,
// _In_opt_ const ebpf_attach_type_t* attach_type,
// _In_reads_bytes_opt_(attach_parameters_size) void* attach_parameters,
// size_t attach_parameters_size,
// _Outptr_ struct bpf_link** link)
var ebpfProgramAttachByFd = efw.Module.NewProc("ebpf_program_attach_by_fd")

// fd_t ebpf_link_fd(_Frees_ptr_ struct bpf_link* link)
var ebpfLinkFree = efw.Module.NewProc("ebpf_link_free")

// const ebpf_attach_type_t* ebpf_get_ebpf_attach_type(bpf_attach_type_t bpf_attach_type)
var ebpfGetEbpfAttachType = efw.Module.NewProc("ebpf_get_ebpf_attach_type")

func AttachRawLink(opts RawLinkOptions) (*RawLink, error) {
	if opts.Target != 0 || opts.BTF != 0 || opts.Flags != 0 {
		return nil, fmt.Errorf("specified option(s) %w", internal.ErrNotSupportedOnOS)
	}

	attachType, err := efw.CallPointer(ebpfGetEbpfAttachType, uintptr(opts.Attach))
	if err != nil {
		return nil, fmt.Errorf("get attach type: %w", err)
	}

	var link uintptr
	err = efw.CallResult(ebpfProgramAttachByFd,
		uintptr(opts.Program.FD()),
		attachType,
		0, // attach_parameters
		0, // attach_parameters_size
		uintptr(unsafe.Pointer(&link)),
	)
	runtime.KeepAlive(opts.Program)
	if err != nil {
		return nil, fmt.Errorf("attach link: %w", err)
	}

	raw, err := efw.CallFd(ebpfLinkFree, link)
	if err != nil {
		return nil, fmt.Errorf("link fd: %w", err)
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
