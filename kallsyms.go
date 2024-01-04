package ebpf

import "github.com/cilium/ebpf/internal/kallsyms"

// FlushKernelModuleCache removes any cached information about function to kernel module mapping.
func FlushKernelModuleCache() {
	kallsyms.FlushKernelModuleCache()
}
