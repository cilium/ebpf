package features

import "github.com/cilium/ebpf/internal"

// LinuxVersionCode returns the version of the currently running kernel
// as defined in the LINUX_VERSION_CODE compile-time macro.
//
// The kernel version and patch level are represented as a single value
// equal to the KERNEL_VERSION macro from linux/version.h.
func LinuxVersionCode() (uint32, error) {
	v, err := internal.KernelVersion()
	if err != nil {
		return 0, err
	}
	return v.Kernel(), nil
}
