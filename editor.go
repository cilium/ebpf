package ebpf

import (
	"fmt"
	"github.com/pkg/errors"
)

// Editor modifies eBPF instructions.
type Editor struct {
	instructions  *Instructions
	refs          map[string][]int
	offsets       map[*Instruction]int
	encodedLength int
}

// Edit creates a new Editor.
//
// The editor retains a reference to insns and modifies its
// contents.
func Edit(insns *Instructions) *Editor {
	refs := make(map[string][]int)
	offsets := make(map[*Instruction]int, len(*insns))
	encodedLength := 0
	for i, ins := range *insns {
		insPtr := &(*insns)[i]
		offsets[insPtr] = encodedLength
		encodedLength += ins.EncodedLength()

		if ins.Reference != "" {
			refs[ins.Reference] = append(refs[ins.Reference], i)
		}
	}
	return &Editor{insns, refs, offsets, encodedLength}
}

// ReferencedSymbols returns all referenced symbols.
//
// Each name appears only once, but the order is not guaranteed.
func (ed *Editor) ReferencedSymbols() []string {
	var out []string
	for ref := range ed.refs {
		out = append(out, ref)
	}
	return out
}

// RewriteMap rewrites a symbol to point at a Map.
//
// Use IsUnreferencedSymbol if you want to rewrite potentially
// unused maps.
func (ed *Editor) RewriteMap(symbol string, m *Map) error {
	indices := ed.refs[symbol]
	if len(indices) == 0 {
		return &unreferencedSymbolError{symbol}
	}

	for _, index := range indices {
		load := &(*ed.instructions)[index]
		if load.OpCode != LdDW {
			return errors.Errorf("symbol %v: missing load instruction", symbol)
		}

		load.SrcRegister = 1
		load.Constant = int64(m.fd)
	}

	return nil
}

// RewriteConstant rewrites all loads of a symbol to a constant value.
//
// This is a hacky way to change constants in your clang-compiled eBPF
// byte code at load time. Use the following macro in your eBPF to
// access the constant:
//
//    const uint64_t MY_CONSTANT;
//    #define VALUE_OF(x) ((typeof(x))(&x))
//
//    int xdp() {
//        if (VALUE_OF(MY_CONSTANT)) ...
//    }
//
// Normally, using a global const doesn't work since clang expects
// that global to be set up by the loader. For this is emits a load
// and a dereference for each use of MY_CONSTANT, which on a normal
// platform would be rewritten to an address somewhere in memory.
// Since the eBPF VM doesn't have shared memory we can't really allocate
// the global anywhere, and the deref points at invalid memory.
//
// Using this function with the macro works around this by only ever
// looking at the address of the constant. In this case clang doesn't
// emit a deref, and we can use the address as a 64bit constant.
//
// Use IsUnreferencedSymbol if you want to rewrite potentially
// unused symbols.
func (ed *Editor) RewriteConstant(symbol string, value uint64) error {
	indices := ed.refs[symbol]
	if len(indices) == 0 {
		return &unreferencedSymbolError{symbol}
	}
	for _, index := range indices {
		load := &(*ed.instructions)[index]
		if load.OpCode != LdDW {
			return errors.Errorf("symbol %v: missing load instruction", symbol)
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
func (ed *Editor) Link(sections ...Instructions) error {
	// A map of symbols to the libraries which contain them.
	symbols := make(map[string]*linkEditor)
	for i, section := range sections {
		editor, err := newLinkEditor(section)
		if err != nil {
			return errors.Wrapf(err, "section %d", i)
		}
		for symbol := range editor.symbols {
			if symbols[symbol] != nil {
				return errors.Errorf("symbol %s is present in multiple sections", symbol)
			}
			symbols[symbol] = editor
		}
	}

	// Appending to ed.instructions would invalidate the pointers in
	// ed, so instead we append to a new slice and join them at the end.
	var linkedInsns Instructions

	// A list of already linked sections and the offset at which they were
	// linked, to avoid linking multiple times.
	linkedSections := make(map[*linkEditor]int)
	linkedLength := 0

	for symbol, indices := range ed.refs {
		for _, index := range indices {
			ins := &(*ed.instructions)[index]

			if ins.OpCode != Call || ins.SrcRegister != Reg1 {
				continue
			}

			if ins.Constant != -1 {
				// This is already a valid call, do not rewrite it.
				continue
			}

			section := symbols[symbol]
			if section == nil {
				return errors.Errorf("symbol %s missing from libaries", symbol)
			}

			sectionOffset, ok := linkedSections[section]
			if !ok {
				sectionOffset = ed.encodedLength + linkedLength
				linkedLength += section.encodedLength
				linkedInsns = append(linkedInsns, *section.instructions...)
				linkedSections[section] = sectionOffset
			}

			insOffset := ed.offsets[ins]
			funcOffset := section.offsets[section.symbols[symbol]]

			// Calls are relative from the PC after the call instruction.
			// Calculate offset and adjust by one.
			ins.Constant = int64(sectionOffset + funcOffset - insOffset - 1)
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

type linkEditor struct {
	*Editor
	symbols map[string]*Instruction
}

func newLinkEditor(insns Instructions) (*linkEditor, error) {
	symbols := make(map[string]*Instruction)

	for i, ins := range insns {
		insPtr := &insns[i]

		if ins.Symbol == "" {
			continue
		}

		if symbols[ins.Symbol] != nil {
			return nil, errors.Errorf("duplicate label %s", ins.Symbol)
		}

		symbols[ins.Symbol] = insPtr
	}

	return &linkEditor{
		Edit(&insns),
		symbols,
	}, nil
}
