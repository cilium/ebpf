package link

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"

	"golang.org/x/xerrors"
)

type RawAttachProgramOptions struct {
	// File descriptor to attach to. This differs for each attach type.
	Target int
	// Program to attach.
	Program *ebpf.Program
	// Program to replace (cgroups).
	Replace *ebpf.Program
	// Attach must match the attach type of Program (and Replace).
	Attach ebpf.AttachType
	// Flags control the attach behaviour. This differs for each attach type.
	Flags uint32
}

// RawAttachProgram is a low level wrapper around BPF_PROG_ATTACH.
//
// You should use one of the higher level abstractions available in this
// package if possible.
func RawAttachProgram(opts RawAttachProgramOptions) error {
	if err := haveProgAttach(); err != nil {
		return err
	}

	var replaceFd uint32
	if opts.Replace != nil {
		replaceFd = uint32(opts.Replace.FD())
	}

	attr := bpfProgAlterAttr{
		targetFd:     uint32(opts.Target),
		attachBpfFd:  uint32(opts.Program.FD()),
		replaceBpfFd: replaceFd,
		attachType:   opts.Attach,
		attachFlags:  uint32(opts.Flags),
	}

	if err := bpfProgAlter(internal.BPF_PROG_ATTACH, &attr); err != nil {
		return xerrors.Errorf("can't attach program: %s", err)
	}
	return nil
}

type RawDetachProgramOptions struct {
	Target  int
	Program *ebpf.Program
	Attach  ebpf.AttachType
}

// RawDetachProgram is a low level wrapper around BPF_PROG_DETACH.
//
// You should use one of the higher level abstractions available in this
// package if possible.
func RawDetachProgram(opts RawDetachProgramOptions) error {
	if err := haveProgAttach(); err != nil {
		return err
	}

	attr := bpfProgAlterAttr{
		targetFd:    uint32(opts.Target),
		attachBpfFd: uint32(opts.Program.FD()),
		attachType:  opts.Attach,
	}
	if err := bpfProgAlter(internal.BPF_PROG_DETACH, &attr); err != nil {
		return xerrors.Errorf("can't detach program: %s", err)
	}

	return nil
}
