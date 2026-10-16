// Package kfunc resolves kernel function BTF IDs by name.
package kfunc

import (
	"errors"

	"github.com/cilium/ebpf/btf"
)

// IDs returns the BTF type IDs of kernel functions matching names.
//
// If onePerName is true, each name must match exactly one function.
// Otherwise all matching functions are returned.
func IDs(names []string, onePerName bool) ([]btf.TypeID, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, err
	}

	return ids(spec, names, onePerName)
}

func ids(spec *btf.Spec, names []string, onePerName bool) ([]btf.TypeID, error) {
	ids := make([]btf.TypeID, 0, len(names))
	seen := make(map[btf.TypeID]struct{})
	for _, name := range names {
		if onePerName {
			var fn *btf.Func
			if err := spec.TypeByName(name, &fn); err != nil {
				return nil, err
			}

			id, err := spec.TypeID(fn)
			if err != nil {
				return nil, err
			}
			if _, ok := seen[id]; !ok {
				ids = append(ids, id)
				seen[id] = struct{}{}
			}
			continue
		}

		types, err := spec.AnyTypesByName(name)
		if errors.Is(err, btf.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}

		for _, typ := range types {
			fn, ok := typ.(*btf.Func)
			if !ok {
				continue
			}

			id, err := spec.TypeID(fn)
			if err != nil {
				return nil, err
			}
			if _, ok := seen[id]; ok {
				continue
			}

			ids = append(ids, id)
			seen[id] = struct{}{}
		}
	}

	if len(ids) == 0 {
		return nil, btf.ErrNotFound
	}

	return ids, nil
}
