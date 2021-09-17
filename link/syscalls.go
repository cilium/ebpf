package link

import (
	"errors"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

// Type is the kind of link.
type Type uint32

// Valid link types.
//
// Equivalent to enum bpf_link_type.
const (
	UnspecifiedType Type = iota
	RawTracepointType
	TracingType
	CgroupType
	IterType
	NetNsType
	XDPType
)

var haveProgAttach = internal.FeatureTest("BPF_PROG_ATTACH", "4.10", func() error {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.CGroupSKB,
		AttachType: ebpf.AttachCGroupInetIngress,
		License:    "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return internal.ErrNotSupported
	}

	// BPF_PROG_ATTACH was introduced at the same time as CGgroupSKB,
	// so being able to load the program is enough to infer that we
	// have the syscall.
	prog.Close()
	return nil
})

var haveProgAttachReplace = internal.FeatureTest("BPF_PROG_ATTACH atomic replacement", "5.5", func() error {
	if err := haveProgAttach(); err != nil {
		return err
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.CGroupSKB,
		AttachType: ebpf.AttachCGroupInetIngress,
		License:    "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return internal.ErrNotSupported
	}
	defer prog.Close()

	// We know that we have BPF_PROG_ATTACH since we can load CGroupSKB programs.
	// If passing BPF_F_REPLACE gives us EINVAL we know that the feature isn't
	// present.
	attr := sys.ProgAttachAttr{
		// We rely on this being checked after attachFlags.
		TargetFd:    ^uint32(0),
		AttachBpfFd: uint32(prog.FD()),
		AttachType:  uint32(ebpf.AttachCGroupInetIngress),
		AttachFlags: uint32(flagReplace),
	}

	_, err = sys.BPF(&attr)
	if errors.Is(err, unix.EINVAL) {
		return internal.ErrNotSupported
	}
	if errors.Is(err, unix.EBADF) {
		return nil
	}
	return err
})

var haveBPFLink = internal.FeatureTest("bpf_link", "5.7", func() error {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.CGroupSKB,
		AttachType: ebpf.AttachCGroupInetIngress,
		License:    "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return internal.ErrNotSupported
	}
	defer prog.Close()

	attr := sys.LinkCreateAttr{
		// This is a hopefully invalid file descriptor, which triggers EBADF.
		TargetFd:   ^uint32(0),
		ProgFd:     uint32(prog.FD()),
		AttachType: sys.AttachType(ebpf.AttachCGroupInetIngress),
	}
	_, err = sys.BPFFd(&attr)
	if errors.Is(err, unix.EINVAL) {
		return internal.ErrNotSupported
	}
	if errors.Is(err, unix.EBADF) {
		return nil
	}
	return err
})
