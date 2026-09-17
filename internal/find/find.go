package find

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/unix"
)

// TargetInKernel attempts to find a named type in the current kernel.
//
// target will point at the found type after a successful call. Searches both
// vmlinux and any loaded modules.
//
// Returns a non-nil handle if the type was found in a module, [btf.ErrNotFound]
// if the type wasn't found or if BTF is not enabled.
func TargetInKernel[T btf.Type](typeName string, target *T, cache *btf.Cache) (*btf.Spec, *btf.Handle, error) {
	kernelSpec, err := cache.Kernel()
	if err != nil {
		return nil, nil, fmt.Errorf("load kernel spec: %w (%w)", btf.ErrNotFound, err)
	}

	err = kernelSpec.TypeByName(typeName, target)
	if errors.Is(err, btf.ErrNotFound) {
		spec, module, err := findTargetInModule(typeName, target, cache)
		if err != nil {
			// EPERM may be returned when we do not have CAP_SYS_ADMIN.
			// Wrap error with btf.ErrNotFound so callers can handle it accordingly.
			if errors.Is(err, unix.EPERM) {
				return spec, nil, fmt.Errorf("find target in modules: %w (%w)", btf.ErrNotFound, err)
			}

			return nil, nil, fmt.Errorf("find target in modules: %w", err)
		}
		return spec, module, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("find target in vmlinux: %w", err)
	}
	return kernelSpec, nil, err
}

// findTargetInModule attempts to find a named type in any loaded module.
//
// base must contain the kernel's types and is used to parse kmod BTF. Modules
// are searched in the order they were loaded.
//
// Returns btf.ErrNotFound if the target can't be found in any module.
func findTargetInModule[T btf.Type](typeName string, target *T, cache *btf.Cache) (*btf.Spec, *btf.Handle, error) {
	it := new(btf.HandleIterator)
	defer it.Handle.Close()

	for it.Next() {
		info, err := it.Handle.Info()
		if err != nil {
			return nil, nil, fmt.Errorf("get info for BTF ID %d: %w", it.ID, err)
		}

		if !info.IsModule() {
			continue
		}

		spec, err := cache.Module(info.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("parse types for module %s: %w", info.Name, err)
		}

		err = spec.TypeByName(typeName, target)
		if errors.Is(err, btf.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, nil, fmt.Errorf("lookup type in module %s: %w", info.Name, err)
		}

		return spec, it.Take(), nil
	}
	if err := it.Err(); err != nil {
		return nil, nil, fmt.Errorf("iterate modules: %w", err)
	}

	return nil, nil, btf.ErrNotFound
}
