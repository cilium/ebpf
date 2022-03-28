package ebpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/asm"
)

// splitSymbols splits insns into subsections delimited by Symbol Instructions.
// insns cannot be empty and must start with a Symbol Instruction.
//
// The resulting map is indexed by Symbol name.
func splitSymbols(insns asm.Instructions) (map[string]asm.Instructions, error) {
	if len(insns) == 0 {
		return nil, errors.New("insns is empty")
	}

	if insns[0].Symbol() == "" {
		return nil, errors.New("insns must start with a Symbol")
	}

	var name string
	progs := make(map[string]asm.Instructions)
	for _, ins := range insns {
		if sym := ins.Symbol(); sym != "" {
			if progs[sym] != nil {
				return nil, fmt.Errorf("insns contains duplicate Symbol %s", sym)
			}
			name = sym
		}

		progs[name] = append(progs[name], ins)
	}

	return progs, nil
}

// The linker is responsible for resolving bpf-to-bpf calls between programs
// within an ELF. Each BPF program must be a self-contained binary blob,
// so when an instruction in one ELF program section wants to jump to
// a function in another, the linker needs to pull in the bytecode
// (and BTF info) of the target function and concatenate the instruction
// streams.
//
// Later on in the pipeline, all call sites are fixed up with relative jumps
// within this newly-created instruction stream to then finally hand off to
// the kernel with BPF_PROG_LOAD.
//
// Each function is denoted by an ELF symbol and the compiler takes care of
// register setup before each jump instruction.

// linkPrograms resolves bpf-to-bpf calls for a set of programs.
func linkPrograms(progs map[string]*ProgramSpec) map[string]*ProgramSpec {
	// Pre-calculate all function references.
	refs := make(map[*ProgramSpec][]string)
	for _, prog := range progs {
		refs[prog] = prog.Instructions.FunctionReferences()
	}

	// Create a flattened instruction stream, but don't modify progs yet to
	// avoid linking multiple times.
	flattened := make(map[string]asm.Instructions)
	for name, p := range progs {
		if p.SectionName == ".text" {
			// Hide programs (e.g. library functions) that were not explicitly emitted
			// to an ELF section.
			continue
		}

		flattened[name] = flattenInstructions(p, progs, refs)
	}

	// Finally, assign the flattened instructions.
	linkedProgs := make(map[string]*ProgramSpec)
	for name, insns := range flattened {
		prog := progs[name]
		prog.Instructions = insns
		linkedProgs[name] = prog
	}

	return linkedProgs
}

// flattenInstructions resolves bpf-to-bpf calls for a single program.
//
// Flattens the instructions of prog, using progs to resolve the references given
// in refs.
func flattenInstructions(prog *ProgramSpec, progs map[string]*ProgramSpec, refs map[*ProgramSpec][]string) asm.Instructions {
	var (
		linked  = make(map[string]bool)
		pending = refs[prog][:]
		insns   = prog.Instructions[:]
	)

	// Reset cap to force copying when appending.
	pending = pending[:len(pending):len(pending)]
	insns = insns[:len(insns):len(insns)]

	for len(pending) > 0 {
		var ref string
		ref, pending = pending[0], pending[1:]

		if linked[ref] {
			continue
		}

		progRef := progs[ref]
		if progRef == nil {
			// TODO: Is this legitimate?
			continue
		}

		insns = append(insns, progRef.Instructions...)
		pending = append(pending, refs[progRef]...)
		linked[ref] = true
	}

	return insns
}

// fixupAndValidate is called by the ELF reader right before marshaling the
// instruction stream. It performs last-minute adjustments to the program and
// runs some sanity checks before sending it off to the kernel.
func fixupAndValidate(insns asm.Instructions) error {
	iter := insns.Iterate()
	for iter.Next() {
		ins := iter.Ins

		// Map load was tagged with a Reference, but does not contain a Map pointer.
		if ins.IsLoadFromMap() && ins.Reference() != "" && ins.Map() == nil {
			return fmt.Errorf("instruction %d: map %s: %w", iter.Index, ins.Reference(), asm.ErrUnsatisfiedMapReference)
		}

		fixupProbeReadKernel(ins)
	}

	return nil
}

// fixupProbeReadKernel replaces calls to bpf_probe_read_{kernel,user}(_str)
// with bpf_probe_read(_str) on kernels that don't support it yet.
func fixupProbeReadKernel(ins *asm.Instruction) {
	if !ins.IsBuiltinCall() {
		return
	}

	// Kernel supports bpf_probe_read_kernel, nothing to do.
	if haveProbeReadKernel() == nil {
		return
	}

	switch asm.BuiltinFunc(ins.Constant) {
	case asm.FnProbeReadKernel, asm.FnProbeReadUser:
		ins.Constant = int64(asm.FnProbeRead)
	case asm.FnProbeReadKernelStr, asm.FnProbeReadUserStr:
		ins.Constant = int64(asm.FnProbeReadStr)
	}
}
