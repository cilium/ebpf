package ebpf

import (
	"github.com/pkg/errors"
)

// Editor modifies eBPF instructions.
type Editor struct {
	instructions  *Instructions
	refs          map[string][]int
	encodedLength int
}

// Edit creates a new Editor.
//
// The editor retains a reference to insns and modifies its
// contents.
func Edit(insns *Instructions) *Editor {
	refs := make(map[string][]int)
	encodedLength := 0
	for i, ins := range *insns {
		encodedLength += ins.EncodedLength()
		if ins.Reference != "" {
			refs[ins.Reference] = append(refs[ins.Reference], i)
		}
	}
	return &Editor{insns, refs, encodedLength}
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
func (ed *Editor) RewriteMap(symbol string, m *Map) error {
	return ed.rewriteSymbol(symbol, []uint8{LdDW}, func(insns []*Instruction) error {
		insns[0].SrcRegister = 1
		insns[0].Constant = int64(m.fd)
		return nil
	})
}

// RewriteUint64 rewrites a reference to a 64bit global variable to a constant.
//
// This is meant to be used with code emitted by LLVM, not hand written assembly.
func (ed *Editor) RewriteUint64(symbol string, value uint64) error {
	return ed.rewriteRelocation(symbol, LdXDW, int64(value))
}

// RewriteUint32 rewrites all references to a 32bit global variable to a constant.
//
// This is meant to be used with code emitted by LLVM, not hand written assembly.
func (ed *Editor) RewriteUint32(symbol string, value uint32) error {
	return ed.rewriteRelocation(symbol, LdXW, int64(value))
}

// RewriteUint16 rewrites all references to a 32bit global variable to a constant.
//
// This is meant to be used with code emitted by LLVM, not hand written assembly.
func (ed *Editor) RewriteUint16(symbol string, value uint16) error {
	return ed.rewriteRelocation(symbol, LdXH, int64(value))
}

// rewriteRelocation deals with references to global variables as emitted by LLVM.
// When compiled they are represented by a dummy load instruction (which has a zero immediate)
// and a derefencing operation for the correct size.
func (ed *Editor) rewriteRelocation(symbol string, opCode uint8, value int64) error {
	return ed.rewriteSymbol(symbol, []uint8{LdDW, opCode}, func(insns []*Instruction) error {
		load := insns[0]
		deref := insns[1]

		if deref.Offset != 0 {
			return errors.Errorf("symbol %v: scalar accessed as an array")
		}

		// Rewrite original load to new value
		load.Constant = value

		// Replace the deref with a mov
		*deref = Instruction{
			OpCode:      MovSrc,
			DstRegister: deref.DstRegister,
			SrcRegister: load.DstRegister,
		}

		return nil
	})
}

func (ed *Editor) rewriteSymbol(symbol string, opCodes []uint8, fn func([]*Instruction) error) error {
	indices := ed.refs[symbol]
	if len(indices) == 0 {
		return errors.Errorf("unknown symbol %v", symbol)
	}
	for _, index := range indices {
		if index+len(opCodes) > len(*ed.instructions) {
			return errors.Errorf("symbol %v: expected at least %d instructions", len(opCodes))
		}

		insns := make([]*Instruction, 0, len(opCodes))
		for j, opCode := range opCodes {
			ins := &(*ed.instructions)[index+j]
			if ins.OpCode != opCode {
				return errors.Errorf("symbol %v: expected instruction %#x at offset+%d", symbol, opCode, j)
			}
			insns = append(insns, ins)
		}

		if err := fn(insns); err != nil {
			return err
		}
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
				return errors.Errorf("symbol %s is present in multiple sections")
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
				return errors.Errorf("symbol %s missing from libaries")
			}

			sectionOffset, ok := linkedSections[section]
			if !ok {
				sectionOffset = ed.encodedLength + linkedLength
				linkedLength += section.encodedLength
				linkedInsns = append(linkedInsns, *section.instructions...)
				linkedSections[section] = sectionOffset
			}

			// The program counter is already pointing at the instruction after Call
			// when the call occurs, so adjust the offset by one.
			ins.Constant = int64(sectionOffset + section.offsets[section.symbols[symbol]] - 1)
		}
	}

	// ed.instructions has been fixed up. Append linked instructions and
	// recalculate ed.
	*ed.instructions = append(*ed.instructions, linkedInsns...)
	*ed = *Edit(ed.instructions)
	return nil
}

type linkEditor struct {
	*Editor
	symbols map[string]*Instruction
	offsets map[*Instruction]int
}

func newLinkEditor(insns Instructions) (*linkEditor, error) {
	symbols := make(map[string]*Instruction)
	offsets := make(map[*Instruction]int)
	length := 0

	for i, ins := range insns {
		insPtr := &insns[i]
		offsets[insPtr] = length
		length += ins.EncodedLength()

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
		offsets,
	}, nil
}
