package link

import (
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
	"golang.org/x/xerrors"
)

type bpfProgAlterAttr struct {
	targetFd     uint32
	attachBpfFd  uint32
	attachType   ebpf.AttachType
	attachFlags  uint32
	replaceBpfFd uint32
}

func bpfProgAlter(cmd internal.BPFCmd, attr *bpfProgAlterAttr) error {
	_, err := internal.BPF(cmd, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

var haveProgAttach = internal.FeatureTest("BPF_PROG_ATTACH", "4.10", func() (bool, error) {
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
		return false, nil
	}

	// BPF_PROG_ATTACH was introduced at the same time as CGgroupSKB,
	// so being able to load the program is enough to infer that we
	// have the syscall.
	prog.Close()
	return true, nil
})

type bpfLinkCreateAttr struct {
	progFd     uint32
	targetFd   uint32
	attachType ebpf.AttachType
	flags      uint32
}

func bpfLinkCreate(attr *bpfLinkCreateAttr) (*internal.FD, error) {
	ptr, err := internal.BPF(internal.BPF_LINK_CREATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	if err == nil {
		return internal.NewFD(uint32(ptr)), nil
	}
	return nil, err
}

type bpfLinkUpdateAttr struct {
	linkFd    uint32
	newProgFd uint32
	flags     uint32
	oldProgFd uint32
}

func bpfLinkUpdate(attr *bpfLinkUpdateAttr) error {
	_, err := internal.BPF(internal.BPF_LINK_UPDATE, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

var haveBPFLink = internal.FeatureTest("bpf_link", "5.7", func() (bool, error) {
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
		return false, nil
	}
	defer prog.Close()

	attr := bpfLinkCreateAttr{
		// This is a hopefully invalid file descriptor, which triggers EBADF.
		targetFd:   ^uint32(0),
		progFd:     uint32(prog.FD()),
		attachType: ebpf.AttachCGroupInetIngress,
	}
	_, err = bpfLinkCreate(&attr)
	return !xerrors.Is(err, unix.EINVAL), nil
})
