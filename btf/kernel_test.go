package btf

import (
	"os"
	"runtime"
	"sync"
	"testing"

	"github.com/cilium/ebpf/internal/testutils"

	"github.com/go-quicktest/qt"
)

func TestLoadKernelSpec(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		t.Skip("/sys/kernel/btf/vmlinux not present")
	}

	spec, err := LoadKernelSpec()
	if err != nil {
		t.Fatal("Can't load kernel spec:", err)
	}

	if !testutils.IsVersionLessThan(t, "linux:6.16") {
		maps, err := os.ReadFile("/proc/self/maps")
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.StringContains(string(maps), " /sys/kernel/btf/vmlinux\n"))
	}

	// Prevent finalizer from unmapping vmlinux.
	runtime.KeepAlive(spec)
}

func TestLoadKernelModuleSpec(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/bpf_testmod"); os.IsNotExist(err) {
		t.Skip("/sys/kernel/btf/bpf_testmod not present")
	}

	_, err := LoadKernelModuleSpec("bpf_testmod")
	qt.Assert(t, qt.IsNil(err))
}

func TestCache(t *testing.T) {
	c := NewCache()

	qt.Assert(t, qt.IsNil(c.kernelTypes))
	qt.Assert(t, qt.HasLen(c.moduleTypes, 0))
	qt.Assert(t, qt.IsNil(c.loadedModules))

	// Test that Kernel() creates only one copy per Cache instance.
	spec1, err := c.Kernel()
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(spec1))

	spec2, err := c.Kernel()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(spec2))

	qt.Assert(t, qt.Equals(spec1, spec2))

	// Test that Module() creates only one copy per Cache instance.
	mod1, err := c.Module("bpf_testmod")
	if !os.IsNotExist(err) {
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsNotNil(mod1))

		mod2, err := c.Module("bpf_testmod")
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsNotNil(mod2))

		qt.Assert(t, qt.Equals(mod1, mod2))
	}

	// Test that Modules only reads modules once.
	_, err = c.Modules()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(c.loadedModules))
}

func TestCacheConcurrentKernel(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		t.Skip("/sys/kernel/btf/vmlinux not present")
	}

	const goroutines = 8

	c := NewCache()
	specs := make([]*Spec, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			specs[i], errs[i] = c.Kernel()
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		qt.Assert(t, qt.IsNil(err))
	}
	for i := 1; i < goroutines; i++ {
		qt.Assert(t, qt.Equals(specs[0], specs[i]))
	}
}

func TestCacheConcurrentModule(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/bpf_testmod"); os.IsNotExist(err) {
		t.Skip("/sys/kernel/btf/bpf_testmod not present")
	}

	const goroutines = 8

	c := NewCache()
	specs := make([]*Spec, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := range goroutines {
		go func(i int) {
			defer wg.Done()
			specs[i], errs[i] = c.Module("bpf_testmod")
		}(i)
	}
	wg.Wait()

	for _, err := range errs {
		qt.Assert(t, qt.IsNil(err))
	}
	for i := 1; i < goroutines; i++ {
		qt.Assert(t, qt.Equals(specs[0], specs[i]))
	}
}
