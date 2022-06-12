package btf_test

import (
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestNewHandleFromID(t *testing.T) {
	// vmlinux is not guaranteed to be at ID 1, but it's highly likely, since
	// module loading causes vmlinux to be parsed.
	const vmlinux = btf.ID(1)

	// See https://github.com/torvalds/linux/commit/5329722057d41aebc31e391907a501feaa42f7d9
	testutils.SkipOnOldKernel(t, "5.11", "vmlinux BTF ID")

	h, err := btf.NewHandleFromID(vmlinux)
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
}
