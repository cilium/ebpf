package features

import "github.com/cilium/ebpf/internal"

// KernelVersion returns the version of the currently running kernel.
// The version uses the format of the kernel's KERNEL_VERSION macro from linux/version.h.
// It represents the kernel version and patch level as a single value.
func KernelVersion() (uint32, error) {
	v, err := internal.KernelVersion()
	if err != nil {
		return 0, err
	}
	return v.Kernel(), nil
}
