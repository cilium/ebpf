package link

import (
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
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
