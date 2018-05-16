package ebpf

import (
	"github.com/pkg/errors"
)

// Editor modifies eBPF instructions.
type Editor struct {
	instructions  *Instructions
	refs          map[string][]*Instruction
	encodedLength int
}

// Edit creates a new Editor.
//
// The editor retains a reference to insns and modifies its
// contents.
func Edit(insns *Instructions) *Editor {
	refs := make(map[string][]*Instruction)
	encodedLength := 0
	for i, ins := range *insns {
		encodedLength += ins.EncodedLength()
		if ins.Reference != "" {
			refs[ins.Reference] = append(refs[ins.Reference], &(*insns)[i])
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
	insns := ed.refs[symbol]
	if len(insns) == 0 {
		return errors.Errorf("unknown symbol %v", symbol)
	}
	for _, ins := range insns {
		if ins.OpCode != LdDW {
			return errors.Errorf("symbol %v: not a valid map symbol, expected LdDW instruction", symbol)
		}
		ins.SrcRegister = 1
		ins.Constant = int64(m.fd)
	}
	return nil
}

// RewriteUint64 rewrites a symbol to a 64bit constant.
func (ed *Editor) RewriteUint64(symbol string, value uint64) error {
	insns := ed.refs[symbol]
	if len(insns) == 0 {
		return errors.Errorf("unknown symbol %v", symbol)
	}
	for _, ins := range insns {
		if ins.OpCode != LdDW {
			return errors.Errorf("symbol %v: expected LdDW instruction", symbol)
		}
		ins.Constant = int64(value)
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

	for symbol, insns := range ed.refs {
		for _, ins := range insns {
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
