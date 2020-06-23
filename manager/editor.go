package manager

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/DataDog/ebpf/asm"
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
