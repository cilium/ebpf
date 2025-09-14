package ebpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/btf"
)

const structOpsValuePrefix = "bpf_struct_ops_"

// findStructTypeByName looks up a struct type with the exact name in the
// provided base BTF spec, and falls back to scanning all loaded module BTFs
// if it is not present in vmlinux.
//
// Search order and behavior:
//  1. vmlinux (base spec): try AnyTypeByName(name). If it exists and is a
//     *btf.Struct, return it immediately with moduleID=0.
//     - If AnyTypeByName returns a non-notfound error, the error is propagated.
//     - If a type is found but is not a *btf.Struct, we fall back to modules.
//  2. modules: see findStructTypeByNameFromModule.
//
// Returns (*btf.Struct, *btf.Spec, moduleID, nil) on success, or btf.ErrNotFound
// if no matching struct is present in vmlinux or any module.
func findStructTypeByName(s *btf.Spec, name string) (*btf.Struct, *btf.Spec, uint32, error) {
	if s == nil {
		return nil, nil, 0, fmt.Errorf("nil BTF: %w", btf.ErrNotFound)
	}

	t, err := s.AnyTypeByName(name)
	if err == nil {
		if typ, ok := btf.As[*btf.Struct](t); ok {
			return typ, s, 0, nil
		}
	} else if !errors.Is(err, btf.ErrNotFound) {
		return nil, nil, 0, err
	}
	return findStructTypeByNameFromModule(s, name)
}

// findStructTypeByNameFromModule scans all loaded kernel modules and tries
// to resolve a struct type with the exact name. The iteration uses the base
// vmlinux spec for string/ID interning as required by btf.Handle.Spec(base).
//
// For the first module where AnyTypeByName(name) returns a *btf.Struct,
// the function returns that struct, the module's *btf.Spec, and its BTF ID.
// If the type is not found in any module, btf.ErrNotFound is returned.
func findStructTypeByNameFromModule(base *btf.Spec, name string) (*btf.Struct, *btf.Spec, uint32, error) {
	it := new(btf.HandleIterator)

	for it.Next() {
		defer it.Handle.Close()

		info, err := it.Handle.Info()
		if err != nil {
			return nil, nil, 0, fmt.Errorf("get info for BTF ID %d: %w", it.ID, err)
		}

		if !info.IsModule() {
			continue
		}

		spec, err := it.Handle.Spec(base)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("parse types for module %s: %w", info.Name, err)
		}

		t, err := spec.AnyTypeByName(name)
		if errors.Is(err, btf.ErrNotFound) {
			continue
		}

		if err != nil {
			return nil, nil, 0, fmt.Errorf("lookup type in module %s: %w", info.Name, err)
		}

		if typ, ok := btf.As[*btf.Struct](t); ok {
			return typ, spec, uint32(it.ID), nil
		}
	}

	return nil, nil, 0, btf.ErrNotFound
}

// getStructMemberIndexByName returns the index of `member` within struct `s` by
// comparing the member name.
func getStructMemberIndexByName(s *btf.Struct, name string) int {
	for idx, m := range s.Members {
		if m.Name == name {
			return idx
		}
	}
	return -1
}
