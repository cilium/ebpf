package btf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/kallsyms"
)

// LoadKernelSpec returns the current kernel's BTF information.
//
// Defaults to /sys/kernel/btf/vmlinux and falls back to scanning the file system
// for vmlinux ELFs. Returns an error wrapping ErrNotSupported if BTF is not enabled.
func LoadKernelSpec() (*Spec, error) {
	spec, _, err := kernelSpec()
	if err != nil {
		return nil, err
	}
	return spec.Copy(), nil
}

// LoadKernelModuleSpec returns the BTF information for the named kernel module.
//
// Defaults to /sys/kernel/btf/<module>.
// Returns an error wrapping ErrNotSupported if BTF is not enabled.
func LoadKernelModuleSpec(module string) (*Spec, error) {
	dir, file := filepath.Split(module)
	if dir != "" || filepath.Ext(file) != "" {
		return nil, fmt.Errorf("invalid module name %q", module)
	}
	spec, err := kernelModuleSpec(module)
	if err != nil {
		return nil, err
	}
	return spec.Copy(), nil
}

var kernelBTF struct {
	sync.RWMutex
	spec *Spec
	// True if the spec was read from an ELF instead of raw BTF in /sys.
	fallback bool
}

var kernelModuleBTF = struct {
	sync.RWMutex
	spec map[string]*Spec
}{
	spec: make(map[string]*Spec),
}

// FlushKernelSpec removes any cached kernel type information.
func FlushKernelSpec() {
	kernelModuleBTF.Lock()
	defer kernelModuleBTF.Unlock()
	kernelBTF.Lock()
	defer kernelBTF.Unlock()

	kernelBTF.spec, kernelBTF.fallback = nil, false
	kernelModuleBTF.spec = make(map[string]*Spec)

	kallsyms.FlushKernelModuleCache()
}

func kernelSpec() (*Spec, bool, error) {
	kernelBTF.RLock()
	spec, fallback := kernelBTF.spec, kernelBTF.fallback
	kernelBTF.RUnlock()

	if spec == nil {
		kernelBTF.Lock()
		defer kernelBTF.Unlock()

		spec, fallback = kernelBTF.spec, kernelBTF.fallback
	}

	if spec != nil {
		return spec, fallback, nil
	}

	spec, fallback, err := loadKernelSpec()
	if err != nil {
		return nil, false, err
	}

	kernelBTF.spec, kernelBTF.fallback = spec, fallback
	return spec, fallback, nil
}

func kernelModuleSpec(module string) (*Spec, error) {
	kernelModuleBTF.RLock()
	spec := kernelModuleBTF.spec[module]
	kernelModuleBTF.RUnlock()

	if spec == nil {
		kernelModuleBTF.Lock()
		defer kernelModuleBTF.Unlock()

		spec = kernelModuleBTF.spec[module]
	}

	if spec != nil {
		return spec, nil
	}

	spec, err := loadKernelModuleSpec(module)
	if err != nil {
		return nil, err
	}

	kernelModuleBTF.spec[module] = spec
	return spec, nil
}

func loadKernelSpec() (_ *Spec, fallback bool, _ error) {
	fh, err := os.Open("/sys/kernel/btf/vmlinux")
	if err == nil {
		defer fh.Close()

		spec, err := loadRawSpec(fh, internal.NativeEndian, nil)
		return spec, false, err
	}

	file, err := findVMLinux()
	if err != nil {
		return nil, false, err
	}
	defer file.Close()

	spec, err := LoadSpecFromReader(file)
	return spec, true, err
}

func loadKernelModuleSpec(module string) (*Spec, error) {
	base, _, err := kernelSpec()
	if err != nil {
		return nil, err
	}

	fh, err := os.Open(filepath.Join("/sys/kernel/btf", module))
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	return loadRawSpec(fh, internal.NativeEndian, base)
}

// findVMLinux scans multiple well-known paths for vmlinux kernel images.
func findVMLinux() (*os.File, error) {
	release, err := internal.KernelRelease()
	if err != nil {
		return nil, err
	}

	// use same list of locations as libbpf
	// https://github.com/libbpf/libbpf/blob/9a3a42608dbe3731256a5682a125ac1e23bced8f/src/btf.c#L3114-L3122
	locations := []string{
		"/boot/vmlinux-%s",
		"/lib/modules/%s/vmlinux-%[1]s",
		"/lib/modules/%s/build/vmlinux",
		"/usr/lib/modules/%s/kernel/vmlinux",
		"/usr/lib/debug/boot/vmlinux-%s",
		"/usr/lib/debug/boot/vmlinux-%s.debug",
		"/usr/lib/debug/lib/modules/%s/vmlinux",
	}

	for _, loc := range locations {
		file, err := os.Open(fmt.Sprintf(loc, release))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		return file, err
	}

	return nil, fmt.Errorf("no BTF found for kernel version %s: %w", release, internal.ErrNotSupported)
}
