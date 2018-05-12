package ebpf

import (
	"fmt"
)

// Editor modifies EBPF instructions at runtime.
type Editor struct {
	instructions *Instructions
	refs         map[string][]*Instruction
}

// Edit creates a new Editor.
//
// The editor retains a reference to insns and modifies its
// contents.
func Edit(insns *Instructions) *Editor {
	refs := make(map[string][]*Instruction)
	for i, ins := range *insns {
		if ins.Reference != "" {
			refs[ins.Reference] = append(refs[ins.Reference], &(*insns)[i])
		}
	}

	return &Editor{insns, refs}
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
		return fmt.Errorf("unknown symbol %v", symbol)
	}
	for _, ins := range insns {
		if ins.OpCode != LdDW {
			return fmt.Errorf("symbol %v: not a valid map symbol, expected LdDW instruction", symbol)
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
		return fmt.Errorf("unknown symbol %v", symbol)
	}
	for _, ins := range insns {
		if ins.OpCode != LdDW {
			return fmt.Errorf("symbol %v: expected LdDw instruction", symbol)
		}
		ins.Constant = int64(value)
	}
	return nil
}
