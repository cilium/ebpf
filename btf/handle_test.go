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
