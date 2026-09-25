package features

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// HaveProgramType probes the running kernel for the availability of the specified program type.
//
// See the package documentation for the meaning of the error return value.
func HaveProgramType(pt ebpf.ProgramType, opts *ProbeOptions) error {
	return kernelHasEnumValue(opts, "bpf_prog_type", uint64(pt))
}

// HaveProgramHelper probes the running kernel for the availability of the specified helper.
//
// See the package documentation for the meaning of the error return value.
func HaveProgramHelper(helper asm.BuiltinFunc, opts *ProbeOptions) error {
	return kernelHasEnumValue(opts, "bpf_func_id", uint64(helper))
}
