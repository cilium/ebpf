// Package kfunc resolves kernel function BTF IDs by name.
package kfunc

import (
	"errors"

	"github.com/cilium/ebpf/btf"
)

// IDs returns the BTF type IDs of up to count kernel functions matching names.
//
// Returns btf.ErrNotFound if fewer than count IDs could be resolved.
func IDs(names []string, count int) ([]btf.TypeID, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, err
	}

	ids := make([]btf.TypeID, 0, count)
	seen := make(map[btf.TypeID]struct{})
	for _, name := range names {
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
			if len(ids) == count {
				return ids, nil
			}
		}
	}

	return nil, btf.ErrNotFound
}
