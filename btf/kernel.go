package btf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/linux"
	"github.com/cilium/ebpf/internal/platform"
)

// globalCache amortises decoding BTF across all users of the library.
var globalCache struct {
	sync.RWMutex
	Cache
}

// Cache allows to amortise the cost of decoding BTF across multiple call-sites.
//
// It is not safe for concurrent use.
type Cache struct {
	kernel  *Spec
	modules map[string]*Spec
}

// NewCache creates a new Cache.
//
// Opportunistically reuses a global cache if possible.
func NewCache() *Cache {
	globalCache.RLock()
	defer globalCache.RUnlock()

	// This copy is either a no-op or very cheap, since the spec won't contain
	// any inflated types.
	kernel := globalCache.kernel.Copy()
	modules := make(map[string]*Spec, len(globalCache.modules))
	for name, spec := range globalCache.modules {
		decoder := spec.decoder.ShallowCopy()
		// Share base between all kernel module specs.
		decoder.base = kernel.decoder
		// NB: Kernel module BTF can't contain ELF fixups because it is always
		// read from sysfs.
		modules[name] = &Spec{decoder: decoder}
	}

	return &Cache{kernel, modules}
}

// Kernel is equivalent to [LoadKernelSpec], except that repeated calls do
// not copy the Spec.
func (c *Cache) Kernel() (*Spec, error) {
	if c.kernel != nil {
		return c.kernel, nil
	}

	var err error
	c.kernel, _, err = loadKernelSpec()
	return c.kernel, err
}

// Module is equivalent to [LoadKernelModuleSpec], except that repeated calls do
// not copy the spec.
//
// All modules also share the return value of [Kernel] as their base.
func (c *Cache) Module(name string) (*Spec, error) {
	if spec := c.modules[name]; spec != nil {
		return spec, nil
	}

	base, err := c.Kernel()
	if err != nil {
		return nil, err
	}

	if c.modules == nil {
		c.modules = make(map[string]*Spec)
	}

	// Important: base is shared between modules. This allows inflating common
	// types only once.
	// We're not reusing the module cache since that requires retargeting
	// spec.base.base.
	spec, err := loadKernelModuleSpec(name, base)
	c.modules[name] = spec
	return spec, err
}

// FlushKernelSpec removes any cached kernel type information.
func FlushKernelSpec() {
	globalCache.Lock()
	globalCache.Cache = Cache{}
	globalCache.Unlock()
}

// LoadKernelSpec returns the current kernel's BTF information.
//
// Defaults to /sys/kernel/btf/vmlinux and falls back to scanning the file system
// for vmlinux ELFs. Returns an error wrapping ErrNotSupported if BTF is not enabled.
//
// Consider using [Cache] instead.
func LoadKernelSpec() (*Spec, error) {
	globalCache.RLock()
	spec := globalCache.kernel
	globalCache.RUnlock()

	if spec != nil {
		return spec.Copy(), nil
	}

	globalCache.Lock()
	defer globalCache.Unlock()

	spec, err := globalCache.Kernel()
	return spec.Copy(), err
}

// LoadKernelModuleSpec returns the BTF information for the named kernel module.
//
// Using [Cache.Module] is faster when loading BTF for more than one module.
//
// Defaults to /sys/kernel/btf/<module>.
// Returns an error wrapping ErrNotSupported if BTF is not enabled.
// Returns an error wrapping fs.ErrNotExist if BTF for the specific module doesn't exist.
func LoadKernelModuleSpec(module string) (*Spec, error) {
	globalCache.RLock()
	spec := globalCache.modules[module]
	globalCache.RUnlock()

	if spec != nil {
		return spec.Copy(), nil
	}

	globalCache.Lock()
	defer globalCache.Unlock()

	spec, err := globalCache.Module(module)
	return spec.Copy(), err
}

func loadKernelSpec() (_ *Spec, fallback bool, _ error) {
	if platform.IsWindows {
		return nil, false, internal.ErrNotSupportedOnOS
	}

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

func loadKernelModuleSpec(module string, base *Spec) (*Spec, error) {
	if platform.IsWindows {
		return nil, internal.ErrNotSupportedOnOS
	}

	dir, file := filepath.Split(module)
	if dir != "" || filepath.Ext(file) != "" {
		return nil, fmt.Errorf("invalid module name %q", module)
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
	if platform.IsWindows {
		return nil, fmt.Errorf("find vmlinux: %w", internal.ErrNotSupportedOnOS)
	}

	release, err := linux.KernelRelease()
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
