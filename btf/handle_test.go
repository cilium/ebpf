package btf_test

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestHandleIterator(t *testing.T) {
	// There is no guarantee that there is a BTF ID allocated, but loading a module
	// triggers loading vmlinux.
	// See https://github.com/torvalds/linux/commit/5329722057d41aebc31e391907a501feaa42f7d9
	testutils.SkipOnOldKernel(t, "5.11", "vmlinux BTF ID")

	var h *btf.Handle
	defer h.Close()

	it := new(btf.HandleIterator)
	if !it.Next(&h) {
		t.Fatalf("No BTF loaded")
	}
	if h == nil {
		t.Fatal("Next doesn't assign handle")
	}
	prev := it.ID
	for it.Next(&h) {
		// Iterate all loaded BTF.
		if h == nil {
			t.Fatal("Next doesn't assign handle")
		}
		if it.ID == prev {
			t.Fatal("Iterator doesn't advance ID")
		}
		prev = it.ID
	}
	if err := it.Err(); err != nil {
		t.Fatal("Iteration returned an error:", err)
	}

	if h != nil {
		t.Fatal("Next doesn't clean up handle on last iteration")
	}
	if prev != it.ID {
		t.Fatal("Next changes ID on last iteration")
	}
}

func TestParseModuleSplitSpec(t *testing.T) {
	// See TestNewHandleFromID for reasoning.
	testutils.SkipOnOldKernel(t, "5.11", "vmlinux BTF ID")

	var module *btf.Handle
	defer module.Close()

	it := new(btf.HandleIterator)
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

	if module == nil {
		t.Fatal("No BTF for kernel module found")
	}

	var vmlinux *btf.Handle
	defer vmlinux.Close()

	it = new(btf.HandleIterator)
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
	if err := it.Err(); err != nil {
		t.Fatal(err)
	}

	if vmlinux == nil {
		t.Fatal("No BTF for kernel found")
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
	// Ensure that handle is cleaned up. This is valid for nil handles as well.
	defer handle.Close()

	it := new(btf.HandleIterator)
	for it.Next(&handle) {
		fmt.Printf("Found handle with ID %d\n", it.ID)
	}
	if err := it.Err(); err != nil {
		panic(err)
	}
}
