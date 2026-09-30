package features

import (
	"fmt"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

type ProbeOptions struct {
	Cache       *btf.Cache
	KernelTypes *btf.Spec
}

func kernelHasEnumValue(opts *ProbeOptions, enumName string, value uint64) error {
	var err error

	if opts == nil {
		opts = &ProbeOptions{Cache: btf.NewCache()}
	}

	spec := opts.KernelTypes
	if spec == nil {
		spec, err = opts.Cache.Kernel()
		if err != nil {
			return err
		}
	}

	var enumType *btf.Enum
	err = spec.TypeByName(enumName, &enumType)
	if err != nil {
		return fmt.Errorf("type 'enum %s' not found: %w", enumName, err)
	}

	found := slices.ContainsFunc(enumType.Values, func(v btf.EnumValue) bool {
		return v.Value == value
	})

	if !found {
		return ebpf.ErrNotSupported
	}

	return nil
}
