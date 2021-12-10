package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/btf"
)

// The linker is responsible for resolving bpf-to-bpf calls between programs
// within an ELF. Each BPF program must be a self-contained binary blob,
// so when an instruction in one ELF program section wants to jump to
// a function in another, the linker needs to pull in the bytecode
// (and BTF info) of the target function and concatenate the instruction
// streams together.
//
// Later on in the pipeline, all call sites are fixed up with relative jumps
// within this newly-created instruction stream to then finally hand off to
// the kernel with BPF_PROG_LOAD.
//
// Each function is denoted by an ELF symbol and the compiler takes care of
// register setup before each jump instruction.

// findReferences finds bpf-to-bpf calls in all given progs.
// It populates each ProgramSpec's references with pointers
// to all other programs directly referenced by its bytecode.
func findReferences(progs map[string]*ProgramSpec) error {
	// Check all ProgramSpecs in the collection against each other.
	for _, caller := range progs {
		// Obtain a list of call targets in the calling program.
		calls := caller.Instructions.FunctionReferences()

		for _, dep := range progs {
			// Don't link a program against itself.
			if caller == dep {
				continue
			}

			if calls[dep.Instructions.Name()] {
				// Register a direct reference to another program.
				caller.references = append(caller.references, dep)
			}
		}
	}

	return nil
}

// collectInstructions returns the instruction stream of all progs in order.
func collectInstructions(progs []*ProgramSpec) asm.Instructions {
	var out asm.Instructions

	for _, prog := range progs {
		out = append(out, prog.Instructions...)
	}

	return out
}

// marshalFuncInfos returns the BTF func infos of all progs in order.
func marshalFuncInfos(progs []*ProgramSpec) ([]byte, error) {
	if len(progs) == 0 {
		return nil, nil
	}

	var off uint64

	buf := bytes.NewBuffer(make([]byte, 0, binary.Size(&btf.FuncInfo{})*len(progs)))
	for _, prog := range progs {
		if err := prog.BTF.FuncInfo.Marshal(buf, off); err != nil {
			return nil, fmt.Errorf("marshaling prog %s func info: %w", prog.Name, err)
		}
		off += prog.Instructions.Size()
	}

	return buf.Bytes(), nil
}

// marshalLineInfos returns the BTF line infos of all progs in order.
func marshalLineInfos(progs []*ProgramSpec) ([]byte, error) {
	if len(progs) == 0 {
		return nil, nil
	}

	var off uint64

	buf := bytes.NewBuffer(make([]byte, 0, binary.Size(&btf.LineInfo{})*len(progs)))
	for _, prog := range progs {
		if err := prog.BTF.LineInfos.Marshal(buf, off); err != nil {
			return nil, fmt.Errorf("marshaling prog %s line infos: %w", prog.Name, err)
		}
		off += prog.Instructions.Size()
	}

	return buf.Bytes(), nil
}

func fixupJumpsAndCalls(insns asm.Instructions) error {
	symbolOffsets := make(map[string]asm.RawInstructionOffset)
	iter := insns.Iterate()
	for iter.Next() {
		ins := iter.Ins

		if ins.Symbol == "" {
			continue
		}

		if _, ok := symbolOffsets[ins.Symbol]; ok {
			return fmt.Errorf("duplicate symbol %s", ins.Symbol)
		}

		symbolOffsets[ins.Symbol] = iter.Offset
	}

	iter = insns.Iterate()
	for iter.Next() {
		i := iter.Index
		offset := iter.Offset
		ins := iter.Ins

		if ins.Reference == "" {
			continue
		}

		symOffset, ok := symbolOffsets[ins.Reference]
		switch {
		case ins.IsLoadOfFunctionPointer() && ins.Constant == -1:
			fallthrough

		case ins.IsFunctionCall() && ins.Constant == -1:
			if !ok {
				break
			}

			ins.Constant = int64(symOffset - offset - 1)
			continue

		case ins.OpCode.Class() == asm.JumpClass && ins.Offset == -1:
			if !ok {
				break
			}

			ins.Offset = int16(symOffset - offset - 1)
			continue

		case ins.IsLoadFromMap() && ins.MapPtr() == -1:
			return fmt.Errorf("map %s: %w", ins.Reference, errUnsatisfiedReference)
		default:
			// no fixup needed
			continue
		}

		return fmt.Errorf("%s at %d: reference to missing symbol %q", ins.OpCode, i, ins.Reference)
	}

	// fixupBPFCalls replaces bpf_probe_read_{kernel,user}[_str] with bpf_probe_read[_str] on older kernels
	// https://github.com/libbpf/libbpf/blob/master/src/libbpf.c#L6009
	iter = insns.Iterate()
	for iter.Next() {
		ins := iter.Ins
		if !ins.IsBuiltinCall() {
			continue
		}
		switch asm.BuiltinFunc(ins.Constant) {
		case asm.FnProbeReadKernel, asm.FnProbeReadUser:
			if err := haveProbeReadKernel(); err != nil {
				ins.Constant = int64(asm.FnProbeRead)
			}
		case asm.FnProbeReadKernelStr, asm.FnProbeReadUserStr:
			if err := haveProbeReadKernel(); err != nil {
				ins.Constant = int64(asm.FnProbeReadStr)
			}
		}
	}

	return nil
}
