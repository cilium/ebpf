package btf

import (
	"os"
	"testing"

	"github.com/cilium/ebpf/internal/testutils"

	"github.com/go-quicktest/qt"
)

func TestLoadKernelSpec(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		t.Skip("/sys/kernel/btf/vmlinux not present")
	}

	_, err := LoadKernelSpec()
	if err != nil {
		t.Fatal("Can't load kernel spec:", err)
	}
}

func TestLoadKernelModuleSpec(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/btf_testmod"); os.IsNotExist(err) {
		t.Skip("/sys/kernel/btf/btf_testmod not present")
	}

	_, err := LoadKernelModuleSpec("btf_testmod")
	qt.Assert(t, qt.IsNil(err))
}

func TestCache(t *testing.T) {
	FlushKernelSpec()
	c := NewCache()

	qt.Assert(t, qt.IsNil(c.KernelTypes))
	qt.Assert(t, qt.HasLen(c.KernelModules, 0))

	// Test that Kernel() creates only one copy
	spec1, err := c.Kernel()
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(spec1))

	spec2, err := c.Kernel()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNotNil(spec2))

	qt.Assert(t, qt.Equals(spec1, spec2))

	// Test that Module() creates only one copy
	mod1, err := c.Module("bpf_testmod")
	if !os.IsNotExist(err) {
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsNotNil(mod1))

		mod2, err := c.Module("bpf_testmod")
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsNotNil(mod2))

		qt.Assert(t, qt.Equals(mod1, mod2))
	}

	// Pre-populate global cache
	vmlinux, err := LoadKernelSpec()
	qt.Assert(t, qt.IsNil(err))

	testmod, err := LoadKernelModuleSpec("bpf_testmod")
	if !os.IsNotExist(err) {
		qt.Assert(t, qt.IsNil(err))
	}

	// Test that NewCache populates from global cache
	c = NewCache()
	qt.Assert(t, qt.IsNotNil(c.KernelTypes))
	qt.Assert(t, qt.Not(qt.Equals(c.KernelTypes, vmlinux)))
	if testmod != nil {
		qt.Assert(t, qt.IsNotNil(c.KernelModules["bpf_testmod"]))
		qt.Assert(t, qt.Not(qt.Equals(c.KernelModules["bpf_testmod"], testmod)))
	}
}
