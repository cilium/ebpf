package link

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf/internal"
)

var ErrSymbolNotFound error

type executable struct {
	// Path of the executable on the filesystem.
	path string
	// Parsed ELF symbols and dynamic symbols.
	symbols map[string]*elf.Symbol
}

// Executable defines an executable program on the filesystem.
// To open a new Executable, use:
//
//	Executable("/bin/bash")
//
// The returned value can then be used to open Links such as Uprobe.
func Executable(path string) (*executable, error) {
	var ex executable

	if path == "" {
		return nil, fmt.Errorf("path cannot be empty")
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open file '%s': %w", path, err)
	}
	defer f.Close()

	ex.path = path

	se, err := internal.NewSafeELFFile(f)
	if err != nil {
		return nil, fmt.Errorf("parse ELF file: %w", err)
	}

	ex.symbols = make(map[string]*elf.Symbol)

	// elf.Symbols and elf.DynamicSymbols return ErrNoSymbols if the section is not found.
	syms, err := se.Symbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("parse ELF symbols: %w", err)
	}
	for _, s := range syms {
		sym := s
		ex.symbols[s.Name] = &sym
	}

	syms, err = se.DynamicSymbols()
	if err != nil && !errors.Is(err, elf.ErrNoSymbols) {
		return nil, fmt.Errorf("parse ELF dynamic symbols: %w", err)
	}
	for _, s := range syms {
		sym := s
		ex.symbols[s.Name] = &sym
	}

	return &ex, nil
}

func (ex *executable) symbolByName(symbol string) (*elf.Symbol, error) {
	if s, ok := ex.symbols[symbol]; ok {
		return s, nil
	}
	return nil, ErrSymbolNotFound
}
