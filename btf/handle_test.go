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

	it := new(btf.HandleIterator)
	defer it.Handle.Close()

	if !it.Next() {
		t.Fatalf("No BTF loaded")
	}
	if it.Handle == nil {
		t.Fatal("Next doesn't assign handle")
	}
	prev := it.ID
	for it.Next() {
		// Iterate all loaded BTF.
		if it.Handle == nil {
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

	if it.Handle != nil {
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
		return info.IsVmlinux()
	})
	if err != nil {
		t.Fatal(err)
	}
	defer vmlinux.Close()

	base, err := vmlinux.Spec(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = module.Spec(base)
	if err != nil {
		t.Fatal("Parse module BTF:", err)
	}
}

func ExampleHandleIterator() {
	it := new(btf.HandleIterator)
	defer it.Handle.Close()

	for it.Next() {
		info, err := it.Handle.Info()
		if err != nil {
			panic(err)
		}

		fmt.Printf("Found handle with ID %d and name %s\n", it.ID, info.Name)
	}
	if err := it.Err(); err != nil {
		panic(err)
	}
}
