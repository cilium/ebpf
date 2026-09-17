package features

import (
	"fmt"
	"slices"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func kernelHasEnumValue(cache *btf.Cache, enumName string, value uint64) error {
	if cache == nil {
		cache = btf.NewCache()
	}

	vmlinux, err := cache.Kernel()
	if err != nil {
		return fmt.Errorf("failed to get kernel BTF: %w", err)
	}

	var enumType *btf.Enum
	err = vmlinux.TypeByName(enumName, &enumType)
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
