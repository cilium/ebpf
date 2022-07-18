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

	module, err := btf.FindHandle(func(info *btf.HandleInfo) bool {
		if info.IsModule() {
			t.Log("Using module", info.Name)
			return true
		}
		return false
	})
	if err != nil {
		t.Fatal(err)
	}
	defer module.Close()

	vmlinux, err := btf.FindHandle(func(info *btf.HandleInfo) bool {
		return info.IsKernel
	})
	if err != nil {
		t.Fatal(err)
	}
	defer vmlinux.Close()

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
