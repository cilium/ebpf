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
// streams.
//
// Later on in the pipeline, all call sites are fixed up with relative jumps
// within this newly-created instruction stream to then finally hand off to
// the kernel with BPF_PROG_LOAD.
//
// Each function is denoted by an ELF symbol and the compiler takes care of
// register setup before each jump instruction.

// populateReferences populates all of progs' Instructions and references
// with their full dependency chains including transient dependencies.
func populateReferences(progs map[string]*ProgramSpec) error {
	type props struct {
		insns asm.Instructions
		refs  map[string]*ProgramSpec
	}

	out := make(map[string]props)

	// Resolve and store direct references between all progs.
	if err := findReferences(progs); err != nil {
		return fmt.Errorf("finding references: %w", err)
	}

	// Flatten all progs' instruction streams.
	for name, prog := range progs {
		insns, refs := prog.flatten(nil)

		prop := props{
			insns: insns,
			refs:  refs,
		}

		out[name] = prop
	}

	// Replace all progs' instructions and references
	for name, props := range out {
		progs[name].Instructions = props.insns
		progs[name].references = props.refs
	}

	return nil
}

// findReferences finds bpf-to-bpf calls between progs and populates each
// prog's references field with its direct neighbours.
func findReferences(progs map[string]*ProgramSpec) error {
	// Check all ProgramSpecs in the collection against each other.
	for _, prog := range progs {
		prog.references = make(map[string]*ProgramSpec)

		// Look up call targets in progs and store pointers to their corresponding
		// ProgramSpecs as direct references.
		for refname := range prog.Instructions.FunctionReferences() {
			ref := progs[refname]
			// Call targets are allowed to be missing from an ELF. This occurs when
			// a program calls into a forward function declaration that is left
			// unimplemented. This is caught at load time during fixups.
			if ref != nil {
				prog.references[refname] = ref
			}
		}
	}

	return nil
}

// marshalFuncInfos returns the BTF func infos of all progs in order.
func marshalFuncInfos(layout []reference) ([]byte, error) {
	if len(layout) == 0 {
		return nil, nil
	}

	buf := bytes.NewBuffer(make([]byte, 0, binary.Size(&btf.FuncInfo{})*len(layout)))
	for _, sym := range layout {
		if err := sym.spec.BTF.FuncInfo.Marshal(buf, sym.offset); err != nil {
			return nil, fmt.Errorf("marshaling prog %s func info: %w", sym.spec.Name, err)
		}
	}

	return buf.Bytes(), nil
}

// marshalLineInfos returns the BTF line infos of all progs in order.
func marshalLineInfos(layout []reference) ([]byte, error) {
	if len(layout) == 0 {
		return nil, nil
	}

	buf := bytes.NewBuffer(make([]byte, 0, binary.Size(&btf.LineInfo{})*len(layout)))
	for _, sym := range layout {
		if err := sym.spec.BTF.LineInfos.Marshal(buf, sym.offset); err != nil {
			return nil, fmt.Errorf("marshaling prog %s line infos: %w", sym.spec.Name, err)
		}
	}

	return buf.Bytes(), nil
}

// fixupAndValidate is called by the ELF reader right before marshaling the
// instruction stream. It performs last-minute adjustments to the program and
// runs some sanity checks before sending it off to the kernel.
func fixupAndValidate(insns asm.Instructions) error {
	iter := insns.Iterate()
	for iter.Next() {
		ins := iter.Ins

		if ins.IsLoadFromMap() && ins.MapPtr() == -1 {
			return fmt.Errorf("instruction %d: map %s: %w", iter.Index, ins.Reference, asm.ErrUnsatisfiedMapReference)
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
