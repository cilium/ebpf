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
	for _, prog := range progs {
		for _, dep := range progs {
			// Don't link a program against itself.
			if prog == dep {
				continue
			}

			need, err := needProg(prog.Instructions, dep.Instructions)
			if err != nil {
				return fmt.Errorf("dependency-checking program '%s' and '%s': %w", prog.Name, dep.Name, err)
			}

			if !need {
				continue
			}

			// Register a direct reference to another program.
			prog.references = append(prog.references, dep)
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

// needProg checks insns for references to symbols in instruction stream dep.
// Returns true if a reference is found from insns to dep.
func needProg(insns, dep asm.Instructions) (bool, error) {
	// A map of symbols to the instructions which contain them.
	symbols, err := dep.SymbolOffsets()
	if err != nil {
		return false, err
	}

	for _, ins := range insns {
		if ins.Reference == "" {
			continue
		}

		if !ins.IsFunctionCall() && !ins.IsLoadOfFunctionPointer() {
			continue
		}

		if ins.Constant != -1 {
			// This is already a valid call, no need to link again.
			continue
		}

		if _, ok := symbols[ins.Reference]; !ok {
			// Symbol isn't available in this section
			continue
		}

		// At this point we know that at least one function in the
		// library is called from insns, so we have to link it.
		return true, nil
	}

	// None of the functions in the section are called.
	return false, nil
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
