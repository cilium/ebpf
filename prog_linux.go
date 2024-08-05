package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/linux"
	"github.com/cilium/ebpf/internal/sys"
)

func adjustProgLoadAttrOS(attr *sys.ProgLoadAttr) error {
	// Kernels before 5.0 (6c4fc209fcf9 "bpf: remove useless version check for prog load")
	// require the version field to be set to the value of the KERNEL_VERSION
	// macro for kprobe-type programs.
	// Overwrite Kprobe program version if set to zero or the magic version constant.
	kv := attr.KernVersion
	if attr.ProgType == sys.ProgType(Kprobe) && (kv == 0 || kv == internal.MagicKernelVersion) {
		v, err := linux.KernelVersion()
		if err != nil {
			return fmt.Errorf("kprobe: detect kernel version: %w", err)
		}
		attr.KernVersion = v.Kernel()
	}

	return nil
}
