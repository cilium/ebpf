package features

import (
	"github.com/cilium/ebpf"
)

// HaveMapType probes the running kernel for the availability of the specified map type.
//
// See the package documentation for the meaning of the error return value.
func HaveMapType(mt ebpf.MapType, opts *ProbeOptions) error {
	return kernelHasEnumValue(opts, "bpf_map_type", uint64(mt))
}
