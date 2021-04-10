package internal

import (
	"debug/elf"
	"fmt"
	"io"
	"os"
	"sync"
)

type SafeELFFile struct {
	*elf.File
}

// NewSafeELFFile reads an ELF safely.
//
// Any panic during parsing is turned into an error. This is necessary since
// there are a bunch of unfixed bugs in debug/elf.
//
// https://github.com/golang/go/issues?q=is%3Aissue+is%3Aopen+debug%2Felf+in%3Atitle
func NewSafeELFFile(r io.ReaderAt) (safe *SafeELFFile, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		safe = nil
		err = fmt.Errorf("reading ELF file panicked: %s", r)
	}()

	file, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}

	return &SafeELFFile{file}, nil
}

// Symbols is the safe version of elf.File.Symbols.
func (se *SafeELFFile) Symbols() (syms []elf.Symbol, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		syms = nil
		err = fmt.Errorf("reading ELF symbols panicked: %s", r)
	}()

	syms, err = se.File.Symbols()
	return
}

// DynamicSymbols is the safe version of elf.File.DynamicSymbols.
func (se *SafeELFFile) DynamicSymbols() (syms []elf.Symbol, err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		syms = nil
		err = fmt.Errorf("reading ELF dynamic symbols panicked: %s", r)
	}()

	syms, err = se.File.DynamicSymbols()
	return
}

// SymbolsCache is an ELF symbols cache.
type SymbolsCache struct {
	cache map[string]map[string]elf.Symbol
	mu    sync.Mutex
}

func NewSymbolsCache() *SymbolsCache {
	var sc SymbolsCache
	sc.cache = make(map[string]map[string]elf.Symbol)
	return &sc
}

func (sc *SymbolsCache) Get(path, symbol string) (*elf.Symbol, error) {
	symsCache, ok := sc.cache[path]
	if !ok {
		return sc.fill(path, symbol)
	}
	sym, ok := symsCache[symbol]
	if !ok {
		return sc.fill(path, symbol)
	}
	return &sym, nil
}

func (sc *SymbolsCache) fill(path, symbol string) (*elf.Symbol, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("symbols cache: failed to open file: %w", err)
	}
	defer f.Close()

	se, err := NewSafeELFFile(f)
	if err != nil {
		return nil, fmt.Errorf("symbols cache: failed to parse ELF file: %w", err)
	}

	// TODO(matt): discuss whether this is the right way to fetch all symbols
	var syms []elf.Symbol
	s, _ := se.Symbols()
	syms = append(syms, s...)
	ds, _ := se.DynamicSymbols()
	syms = append(syms, ds...)

	sc.mu.Lock()
	defer sc.mu.Unlock()

	_, ok := sc.cache[path]
	if !ok {
		sc.cache[path] = make(map[string]elf.Symbol)
	}

	for _, sym := range syms {
		sc.cache[path][sym.Name] = sym
	}

	sym, ok := sc.cache[path][symbol]
	if !ok {
		return nil, fmt.Errorf("symbol '%s' not found in ELF file '%s'", symbol, path)
	}

	return &sym, nil
}
