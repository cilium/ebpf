package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/linux"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestKconfigKernelVersion(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/kconfig-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	var obj struct {
		Main *Program `ebpf:"kernel_version"`
	}

	testutils.SkipOnOldKernel(t, "5.2", "readonly maps")

	err = spec.LoadAndAssign(&obj, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Main.Close()

	ret, _, err := obj.Main.Test(internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	v, err := linux.KernelVersion()
	if err != nil {
		t.Fatalf("getting kernel version: %s", err)
	}

	version := v.Kernel()
	if ret != version {
		t.Fatalf("Expected eBPF to return value %d, got %d", version, ret)
	}
}
