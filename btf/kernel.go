package btf

import (
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/kallsyms"
)

var kernelBTF = struct {
	sync.RWMutex
	kernel  *Spec
	modules map[string]*Spec
}{
	modules: make(map[string]*Spec),
}

// FlushKernelSpec removes any cached kernel type information.
func FlushKernelSpec() {
	kallsyms.FlushKernelModuleCache()

	kernelBTF.Lock()
	defer kernelBTF.Unlock()

	kernelBTF.kernel = nil
	kernelBTF.modules = make(map[string]*Spec)
}

// LoadKernelSpec returns the current kernel's BTF information.
//
// Defaults to /sys/kernel/btf/vmlinux and falls back to scanning the file system
// for vmlinux ELFs. Returns an error wrapping ErrNotSupported if BTF is not enabled.
func LoadKernelSpec() (*Spec, error) {
	if runtime.GOOS != "linux" {
		return nil, internal.ErrNotSupportedOnOS
	}

	kernelBTF.RLock()
	spec := kernelBTF.kernel
	kernelBTF.RUnlock()

	if spec == nil {
		kernelBTF.Lock()
		defer kernelBTF.Unlock()

		spec = kernelBTF.kernel
	}

	if spec != nil {
		return spec.Copy(), nil
	}

	spec, _, err := loadKernelSpec()
	if err != nil {
		return nil, err
	}

	kernelBTF.kernel = spec
	return spec.Copy(), nil
}

// LoadKernelModuleSpec returns the BTF information for the named kernel module.
//
// Defaults to /sys/kernel/btf/<module>.
// Returns an error wrapping ErrNotSupported if BTF is not enabled.
// Returns an error wrapping fs.ErrNotExist if BTF for the specific module doesn't exist.
func LoadKernelModuleSpec(module string) (*Spec, error) {
	if runtime.GOOS != "linux" {
		return nil, internal.ErrNotSupportedOnOS
	}

	kernelBTF.RLock()
	spec := kernelBTF.modules[module]
	kernelBTF.RUnlock()

	if spec != nil {
		return spec.Copy(), nil
	}

	base, err := LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("load kernel spec: %w", err)
	}

	kernelBTF.Lock()
	defer kernelBTF.Unlock()

	if spec = kernelBTF.modules[module]; spec != nil {
		return spec.Copy(), nil
	}

	spec, err = loadKernelModuleSpec(module, base)
	if err != nil {
		return nil, err
	}

	kernelBTF.modules[module] = spec
	return spec.Copy(), nil
}
