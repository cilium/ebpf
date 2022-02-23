package features

import "github.com/cilium/ebpf/internal"

// KernelVersion returns the version of the currently running kernel.
//
// The kernel version and patch level are represented as a single value
// equal to the KERNEL_VERSION macro from linux/version.h.
func KernelVersion() (uint32, error) {
	v, err := internal.KernelVersion()
	if err != nil {
		return 0, err
	}
	return v.Kernel(), nil
}
