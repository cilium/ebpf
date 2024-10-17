package kallsyms

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
)

var errAmbiguousKsym = errors.New("multiple kernel symbols with the same name")

var symAddrs cache[string, uint64]

var kernelModules struct {
	sync.RWMutex
	// function to kernel module mapping
	kmods map[string]string
}

// SymbolModule returns the kernel module providing a given symbol, if any.
func SymbolModule(name string) (string, error) {
	kernelModules.RLock()
	kmods := kernelModules.kmods
	kernelModules.RUnlock()

	if kmods == nil {
		kernelModules.Lock()
		defer kernelModules.Unlock()
		kmods = kernelModules.kmods
	}

	if kmods != nil {
		return kmods[name], nil
	}

	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return "", err
	}
	defer f.Close()

	kmods, err = symbolKmods(f)
	if err != nil {
		return "", err
	}

	kernelModules.kmods = kmods
	return kmods[name], nil
}

// FlushKernelModuleCache removes any cached information about function to kernel module mapping.
func FlushKernelModuleCache() {
	kernelModules.Lock()
	defer kernelModules.Unlock()

	kernelModules.kmods = nil
}

// symbolKmods parses f into a map of function names to kernel module names.
// Only function symbols (tT) provided by a kernel module are included in the
// output.
func symbolKmods(f io.Reader) (map[string]string, error) {
	mods := make(map[string]string)
	r := newReader(f)
	for r.Line() {
		s, err, skip := parseSymbol(r, []rune{'t', 'T'})
		if err != nil {
			return nil, fmt.Errorf("parsing kallsyms line: %w", err)
		}
		if skip {
			continue
		}

		// Lines without a module will have an empty mod field. Avoid inserting
		// these into the map to prevent garbage.
		if s.mod == "" {
			continue
		}

		mods[s.name] = s.mod
	}
	if err := r.Err(); err != nil {
		return nil, fmt.Errorf("reading kallsyms: %w", err)
	}

	return mods, nil
}

// AssignAddresses looks up the addresses of the requested symbols in the kernel
// and assigns them to their corresponding values in the symbols map. Results
// of all lookups are cached, successful or otherwise.
//
// Any symbols missing in the kernel are ignored. Returns an error if multiple
// addresses were found for a symbol.
func AssignAddresses(symbols map[string]uint64) error {
	if len(symbols) == 0 {
		return nil
	}

	// Attempt to fetch symbols from cache.
	request := make(map[string]uint64)
	for name := range symbols {
		if addr, ok := symAddrs.Load(name); ok {
			symbols[name] = addr
			continue
		}

		// Mark the symbol to be read from /proc/kallsyms.
		request[name] = 0
	}
	if len(request) == 0 {
		// All symbols satisfied from cache.
		return nil
	}

	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return err
	}

	if err := assignAddresses(f, request); err != nil {
		return fmt.Errorf("loading symbol addresses: %w", err)
	}

	// Update the cache with the new symbols. Cache all requested symbols even if
	// they weren't found, to avoid repeated lookups.
	for name, addr := range request {
		symAddrs.Store(name, addr)
		symbols[name] = addr
	}

	return nil
}

// assignAddresses assigns kernel symbol addresses read from f to values
// requested by symbols. Don't return when all symbols have been assigned, we
// need to scan the whole thing to make sure the user didn't request an
// ambiguous symbol.
func assignAddresses(f io.Reader, symbols map[string]uint64) error {
	if len(symbols) == 0 {
		return nil
	}
	r := newReader(f)
	for r.Line() {
		s, err, skip := parseSymbol(r, nil)
		if err != nil {
			return fmt.Errorf("parsing kallsyms line: %w", err)
		}
		if skip {
			continue
		}

		existing, requested := symbols[s.name]
		if existing != 0 {
			// Multiple addresses for a symbol have been found. Return a friendly
			// error to avoid silently attaching to the wrong symbol. libbpf also
			// rejects referring to ambiguous symbols.
			return fmt.Errorf("symbol %s(0x%x): duplicate found at address 0x%x: %w", s.name, existing, s.addr, errAmbiguousKsym)
		}
		if requested {
			symbols[s.name] = s.addr
		}
	}
	if err := r.Err(); err != nil {
		return fmt.Errorf("reading kallsyms: %w", err)
	}

	return nil
}

type ksym struct {
	addr uint64
	name string
	mod  string
}

// parseSymbol parses a line from /proc/kallsyms into an address, type, name and
// module. Skip will be true if the symbol doesn't match any of the given symbol
// types. See `man 1 nm` for all available types.
//
// Example line: `ffffffffc1682010 T nf_nat_init  [nf_nat]`
func parseSymbol(r *reader, types []rune) (s ksym, err error, skip bool) {
	for i := 0; r.Word(); i++ {
		switch i {
		// Address of the symbol.
		case 0:
			s.addr, err = strconv.ParseUint(r.Text(), 16, 64)
			if err != nil {
				return s, fmt.Errorf("parsing address: %w", err), false
			}
		// Type of the symbol. Assume the character is ASCII-encoded by converting
		// it directly to a rune, since it's a fixed field controlled by the kernel.
		case 1:
			if len(types) > 0 && !slices.Contains(types, rune(r.Bytes()[0])) {
				return s, nil, true
			}
		// Name of the symbol.
		case 2:
			s.name = r.Text()
		// Kernel module the symbol is provided by.
		case 3:
			s.mod = strings.Trim(r.Text(), "[]")
		// Ignore any future fields.
		default:
			break
		}
	}

	return
}
