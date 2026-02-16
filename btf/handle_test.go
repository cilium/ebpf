package btf_test

import (
	"fmt"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"
)

func TestHandleIterator(t *testing.T) {
	// There is no guarantee that there is a BTF ID allocated, but loading a module
	// triggers loading vmlinux.
	// See https://github.com/torvalds/linux/commit/5329722057d41aebc31e391907a501feaa42f7d9
	testutils.SkipOnOldKernel(t, "5.11", "vmlinux BTF ID")

	it := new(btf.HandleIterator)
	defer it.Handle.Close()

	if !it.Next() {
		testutils.SkipIfNotSupportedOnOS(t, it.Err())
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
	testutils.SkipIfNotSupportedOnOS(t, err)
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

func TestNewHandleFromBTFWithToken(t *testing.T) {
	b, err := btf.NewBuilder([]btf.Type{
		&btf.Int{Name: "example", Size: 4, Encoding: btf.Unsigned},
	})
	qt.Assert(t, qt.IsNil(err))
	buf, err := b.Marshal(nil, nil)
	qt.Assert(t, qt.IsNil(err))

	t.Run("no-cmd", func(t *testing.T) {
		if testutils.RunWithToken(t, testutils.Delegated{
			Cmds: []sys.Cmd{},
			// We need to delegate at least one permission, so picking a random map type that we don't use in this test.
			Maps: []sys.MapType{sys.BPF_MAP_TYPE_ARRAY},
		}) {
			return
		}

		h, err := btf.NewHandleFromRawBTF(buf)
		testutils.SkipIfNotSupported(t, err)
		qt.Assert(t, qt.ErrorIs(err, unix.EPERM))
		h.Close()
	})

	t.Run("success", func(t *testing.T) {
		if testutils.RunWithToken(t, testutils.Delegated{
			Cmds: []sys.Cmd{sys.BPF_BTF_LOAD},
			Maps: []sys.MapType{},
		}) {
			return
		}

		h, err := btf.NewHandleFromRawBTF(buf)
		testutils.SkipIfNotSupported(t, err)
		qt.Assert(t, qt.IsNil(err))
		h.Close()
	})
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
