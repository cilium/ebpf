package btf_test

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestNewHandleFromID(t *testing.T) {
	// There is no guarantee that there is a BTF ID allocated, but loading a module
	// triggers loading vmlinux.
	// See https://github.com/torvalds/linux/commit/5329722057d41aebc31e391907a501feaa42f7d9
	testutils.SkipOnOldKernel(t, "5.11", "vmlinux BTF ID")

	var h *btf.Handle
	defer h.Close()

	it := btf.NewHandleIterator()
	if !it.Next(&h) {
		t.Fatalf("No BTF loaded")
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}
}

func TestParseModuleSplitSpec(t *testing.T) {
	// See TestNewHandleFromID for reasoning.
	testutils.SkipOnOldKernel(t, "5.11", "vmlinux BTF ID")

	var module *btf.Handle
	defer module.Close()

	it := btf.NewHandleIterator()
	for it.Next(&module) {
		info, err := module.Info()
		if err != nil {
			t.Fatal(err)
		}

		if !info.IsModule() {
			continue
		}

		t.Log("Using module", info.Name)
		break
	}
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}

	var vmlinux *btf.Handle
	defer vmlinux.Close()

	it = btf.NewHandleIterator()
	for it.Next(&vmlinux) {
		info, err := vmlinux.Info()
		if err != nil {
			t.Fatal(err)
		}

		if !info.IsVmlinux() {
			continue
		}

		break
	}

	vmlinuxSpec, err := vmlinux.Spec(nil)
	if err != nil {
		t.Fatal("Parse vmlinux BTF:", err)
	}

	_, err = module.Spec(vmlinuxSpec)
	if err != nil {
		t.Fatal("Parse module BTF:", err)
	}

	_, err = module.Spec(nil)
	if err == nil {
		t.Fatal("Parsing module BTF without vmlinux base didn't fail")
	}
}

func ExampleHandleIterator() {
	var handle *btf.Handle
	defer handle.Close()

	it := btf.NewHandleIterator()
	for it.Next(&handle) {
		info, err := handle.Info()
		if err != nil {
			panic(err)
		}

		fmt.Printf("Found handle with name %q\n", info.Name)
	}
	if err := it.Err(); err != nil {
		panic(err)
	}
}
