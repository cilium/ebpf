// Package linux provides type information for the current kernel.
package linux

// This package must only ever re-export internal/linux.

import (
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/linux"
)

// FlushCaches removes any cached kernel type information.
func FlushCaches() {
	linux.FlushCaches()
}

// Types returns type information for the current kernel.
func Types() (*btf.Spec, error) {
	types, err := linux.TypesNoCopy()
	if err != nil {
		return nil, err
	}

	return types.Copy(), nil
}
