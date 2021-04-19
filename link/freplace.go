package link

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/btf"
)

type FreplaceLink struct {
	*RawLink
}

// Freplace attaches the given eBPF program to the function with the
// given name in the given program. Example:
//
//	Freplace("syscalls", "sys_enter_fork")
func AttachFreplace(targetProg *ebpf.Program, name string, prog *ebpf.Program) (*FreplaceLink, error) {
	if err := haveTargetBTF(); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, fmt.Errorf("name cannot be empty: %w", errInvalidInput)
	}
	if targetProg == nil {
		return nil, fmt.Errorf("targetProg cannot be nil: %w", errInvalidInput)
	}
	if prog == nil {
		return nil, fmt.Errorf("prog cannot be nil: %w", errInvalidInput)
	}
	if prog.Type() != ebpf.Extension {
		return nil, fmt.Errorf("eBPF program type %s is not an Extension: %w", prog.Type(), errInvalidInput)
	}

	info, err := targetProg.Info()
	if err != nil {
		return nil, err
	}
	defer info.Close()
	spec, err := btf.HandleSpec(info.BTF)
	if err != nil {
		return nil, err
	}

	var function btf.Func
	if err := spec.FindType(name, &function); err != nil {
		return nil, err
	}

	link, err := AttachRawLink(RawLinkOptions{
		Target:  targetProg.FD(),
		Program: prog,
		Attach:  ebpf.AttachNone,
		BTF:     &function,
	})
	if err != nil {
		return nil, err
	}

	return &FreplaceLink{link}, nil
}

var haveTargetBTF = internal.FeatureTest("bpf_link BTF target", "5.10", func() error {
	instructions := asm.Instructions{
		asm.Call.Label("function"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 0).Sym("function"),
		asm.Return(),
	}
	intType := &btf.Int{
		TypeID:   1,
		Name:     "int",
		Size:     4,
		Encoding: btf.Signed,
		Bits:     32,
	}
	funcProtoType := &btf.FuncProto{
		TypeID: 2,
		Return: intType,
		Params: nil,
	}
	programType := &btf.Func{
		TypeID:  3,
		Name:    "program",
		Type:    funcProtoType,
		Linkage: btf.Global,
	}
	functionType := &btf.Func{
		TypeID:  4,
		Name:    "function",
		Type:    funcProtoType,
		Linkage: btf.Global,
	}
	progBTF, err := btf.NewProgram(
		// FIXME (zeffron 2021-04-16) This serves as a bad example as an
		// asm.Instruction could be two bpf_insns long, meaning the length for
		// the that instruction would be 2.
		uint64(len(instructions)),
		[]btf.Type{
			intType,
			funcProtoType,
			programType,
			functionType,
		},
		[]btf.FuncInfo{
			{InstructionOffset: 0, Type: programType},
			{InstructionOffset: 3, Type: functionType},
		},
		nil,
	)
	if err != nil {
		return fmt.Errorf("bug in bpf_link BTF target feature test: %w", err)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.CGroupSKB,
		AttachType:   ebpf.AttachCGroupInetIngress,
		License:      "MIT",
		Instructions: instructions,
		BTF:          progBTF,
	})
	if err != nil {
		return err
	}
	defer prog.Close()

	replacement, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.Extension,
		AttachType:   ebpf.AttachNone,
		AttachTo:     "function",
		AttachTarget: prog.FD(),
		License:      "MIT",
		Instructions: instructions,
		BTF:          progBTF,
	})
	if err != nil {
		return err
	}
	defer replacement.Close()

	link, err := AttachRawLink(RawLinkOptions{
		Target:  prog.FD(),
		Program: replacement,
		Attach:  ebpf.AttachNone,
		BTF:     functionType,
	})
	if err != nil {
		return ErrNotSupported
	}

	link.Close()
	return nil
})
