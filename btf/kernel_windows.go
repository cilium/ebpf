package btf

import (
	"github.com/cilium/ebpf/internal"
)

func loadKernelSpec() (_ *Spec, fallback bool, _ error) {
	return nil, false, internal.ErrNotSupportedOnOS
}

func loadKernelModuleSpec(module string, base *Spec) (*Spec, error) {
	return nil, internal.ErrNotSupportedOnOS
}
