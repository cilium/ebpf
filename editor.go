package ebpf

import (
	"fmt"

	"github.com/newtools/ebpf/asm"
	"github.com/pkg/errors"
)

// Editor modifies eBPF instructions.
type Editor struct {
	instructions     *asm.Instructions
	ReferenceOffsets map[string][]int
}

// Edit creates a new Editor.
//
// The editor retains a reference to insns and modifies its
// contents.
func Edit(insns *asm.Instructions) *Editor {
	refs := insns.ReferenceOffsets()
	return &Editor{insns, refs}
}

// RewriteMap rewrites a symbol to point at a Map.
//
// Use IsUnreferencedSymbol if you want to rewrite potentially
// unused maps.
func (ed *Editor) RewriteMap(symbol string, m *Map) error {
	return ed.rewriteMap(symbol, m, true)
}

func (ed *Editor) rewriteMap(symbol string, m *Map, overwrite bool) error {
	indices := ed.ReferenceOffsets[symbol]
	if len(indices) == 0 {
		return &unreferencedSymbolError{symbol}
	}

	loadOp := asm.LoadImmOp(asm.DWord)

	for _, index := range indices {
		load := &(*ed.instructions)[index]
		if load.OpCode != loadOp {
			return errors.Errorf("symbol %v: missing load instruction", symbol)
		}

		if !overwrite && load.Constant != 0 {
			return nil
		}

		load.Src = 1
		load.Constant = int64(m.fd)
	}

	return nil
}

// RewriteConstant rewrites all loads of a symbol to a constant value.
//
// This is a way to parameterize clang-compiled eBPF byte code at load
// time.
//
// The following macro should be used to access the constant:
//
//    #define LOAD_CONSTANT(param, var) asm("%0 = " param " ll" : "=r"(var))
//
//    int xdp() {
//        bool my_constant;
//        LOAD_CONSTANT("SYMBOL_NAME", my_constant);
//
//        if (my_constant) ...
//
// Caveats:
//   - The symbol name you pick must be unique
//
//   - Failing to rewrite a symbol will not result in an error,
//     0 will be loaded instead (subject to change)
//
// Use IsUnreferencedSymbol if you want to rewrite potentially
// unused symbols.
func (ed *Editor) RewriteConstant(symbol string, value uint64) error {
	indices := ed.ReferenceOffsets[symbol]
	if len(indices) == 0 {
		return &unreferencedSymbolError{symbol}
	}

	ldDWImm := asm.LoadImmOp(asm.DWord)
	for _, index := range indices {
		load := &(*ed.instructions)[index]
		if load.OpCode != ldDWImm {
			return errors.Errorf("symbol %v: load: found %v instead of %v", symbol, load.OpCode, ldDWImm)
		}

		load.Constant = int64(value)
	}
	return nil
}

// Link resolves bpf-to-bpf calls.
//
// Each section may contain multiple functions / labels, and is only linked
// if the program being edited references one of these functions.
//
// Sections must not require linking themselves.
func (ed *Editor) Link(sections ...asm.Instructions) error {
	sections = append(sections, *ed.instructions)

	// A map of symbols to the libraries which contain them.
	symbols := make(map[string]*asm.Instructions)
	for i, section := range sections {
		offsets, err := section.SymbolOffsets()
		if err != nil {
			return err
		}
		for symbol := range offsets {
			if symbols[symbol] != nil {
				return errors.Errorf("symbol %s is present in multiple sections", symbol)
			}
			symbols[symbol] = &sections[i]
		}
	}

	// Appending to ed.instructions would invalidate the pointers in
	// ed, so instead we append to a new slice and join them at the end.
	var linkedInsns asm.Instructions

	// A list of already linked sections to avoid linking multiple times.
	linkedSections := map[*asm.Instructions]struct{}{
		ed.instructions: struct{}{},
	}

	for symbol, indices := range ed.ReferenceOffsets {
		for _, index := range indices {
			ins := &(*ed.instructions)[index]

			if ins.OpCode.JumpOp() != asm.Call || ins.Src != asm.R1 {
				continue
			}

			if ins.Constant != -1 {
				// This is already a valid call, no need to link again.
				continue
			}

			section := symbols[symbol]
			if section == nil {
				return errors.Errorf("symbol %s missing from libaries", symbol)
			}

			if _, ok := linkedSections[section]; !ok {
				linkedInsns = append(linkedInsns, *section...)
				linkedSections[section] = struct{}{}
			}
		}
	}

	// ed.instructions has been fixed up. Append linked instructions and
	// recalculate ed.
	*ed.instructions = append(*ed.instructions, linkedInsns...)
	*ed = *Edit(ed.instructions)
	return nil
}

type unreferencedSymbolError struct {
	symbol string
}

func (use *unreferencedSymbolError) Error() string {
	return fmt.Sprintf("unreferenced symbol %s", use.symbol)
}

// IsUnreferencedSymbol returns true if err was caused by
// an unreferenced symbol.
func IsUnreferencedSymbol(err error) bool {
	_, ok := err.(*unreferencedSymbolError)
	return ok
}
