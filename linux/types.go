// Package linux provides type information for the current kernel.
package linux

// This package must only ever re-export linuxint.

import (
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/linuxint"
)

// FlushTypes removes any cached kernel type information.
func FlushTypes() {
	linuxint.FlushTypes()
}

// Types returns type information for the current kernel.
func Types() (*btf.Spec, error) {
	types, err := linuxint.TypesNoCopy()
	if err != nil {
		return nil, err
	}

	return types.Copy(), nil
}
