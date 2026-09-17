package features

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// HaveMapType probes the running kernel for the availability of the specified map type.
//
// See the package documentation for the meaning of the error return value.
func HaveMapType(cache *btf.Cache, mt ebpf.MapType) error {
	return kernelHasEnumValue(cache, "bpf_map_type", uint64(mt))
}
