package features

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// HaveProgramType probes the running kernel for the availability of the specified program type.
//
// See the package documentation for the meaning of the error return value.
func HaveProgramType(cache *btf.Cache, pt ebpf.ProgramType) error {
	return kernelHasEnumValue(cache, "bpf_prog_type", uint64(pt))
}

// HaveProgramHelper probes the running kernel for the availability of the specified helper.
// It does not guarantee that a particular program type can use this helper.
// Return values have the following semantics:
//
//	err == nil: The feature is available.
//	errors.Is(err, ebpf.ErrNotSupported): The feature is not available.
//	err != nil: Any errors encountered during probe execution, wrapped.
//
// Note that the latter case may include false negatives, and that program creation may
// succeed despite an error being returned.
// Only `nil` and `ebpf.ErrNotSupported` are conclusive.
func HaveProgramHelper(cache *btf.Cache, helper asm.BuiltinFunc) error {
	return kernelHasEnumValue(cache, "bpf_func_id", uint64(helper))
}
