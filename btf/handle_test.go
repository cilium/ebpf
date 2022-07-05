package btf_test

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestNewHandleFromID(t *testing.T) {
	// There is no guarantee that there is a BTF ID allocated, but loading a module
	// triggers loading vmlinux.
	// See https://github.com/torvalds/linux/commit/5329722057d41aebc31e391907a501feaa42f7d9
	testutils.SkipOnOldKernel(t, "5.11", "vmlinux BTF ID")

	var id btf.ID
	for {
		var err error
		id, err = btf.GetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			t.Fatalf("No BTF loaded")
		}

		if err != nil {
			t.Fatal(err)
		}

		h, err := btf.NewHandleFromID(id)
		if errors.Is(err, os.ErrNotExist) {
			// Likely a race where BTF was unloaded before we could retrieve an fd.
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		h.Close()

		return
	}
}
