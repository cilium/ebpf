package gen

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// CollectGlobalTypes finds all types which are used in the global scope.
//
// This currently includes the types of map keys and values.
func CollectGlobalTypes(spec *ebpf.CollectionSpec) []btf.Type {
	var types []btf.Type
	for _, typ := range collectMapTypes(spec.Maps) {
		switch btf.UnderlyingType(typ).(type) {
		case *btf.Datasec:
			// Avoid emitting .rodata, .bss, etc. for now. We might want to
			// name these types differently, etc.
			continue

		case *btf.Int:
			// Don't emit primitive types by default.
			continue
		}

		types = append(types, typ)
	}

	return types
}

// collectMapTypes returns a list of all types used as map keys or values.
func collectMapTypes(maps map[string]*ebpf.MapSpec) []btf.Type {
	var result []btf.Type
	for _, m := range maps {
		if m.Key != nil && m.Key.TypeName() != "" {
			result = append(result, m.Key)
		}

		if m.Value != nil && m.Value.TypeName() != "" {
			result = append(result, m.Value)
		}
	}
	return result
}
