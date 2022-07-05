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
	h := nextHandle(t, &id)
	if h == nil {
		t.Fatalf("No BTF loaded")
	}
	h.Close()
}

func TestParseModuleSplitSpec(t *testing.T) {
	// See TestNewHandleFromID for reasoning.
	testutils.SkipOnOldKernel(t, "5.11", "vmlinux BTF ID")

	var module *btf.Handle
	for id := btf.ID(0); ; {
		module = nextHandle(t, &id)
		if module == nil {
			t.Fatalf("Can't find module BTF")
		}

		info, err := module.Info()
		if err != nil {
			_ = module.Close()
			t.Fatal(err)
		}

		if !info.IsModule() {
			_ = module.Close()
			continue
		}

		break
	}

	var vmlinux *btf.Handle
	for id := btf.ID(0); ; {
		vmlinux = nextHandle(t, &id)
		if vmlinux == nil {
			t.Fatalf("Can't find vmlinux BTF")
		}

		info, err := vmlinux.Info()
		if err != nil {
			_ = vmlinux.Close()
			t.Fatal(err)
		}

		if !info.IsVmlinux() {
			_ = vmlinux.Close()
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

func nextHandle(t *testing.T, prevID *btf.ID) *btf.Handle {
	t.Helper()

	for {
		var err error
		*prevID, err = btf.GetNextID(*prevID)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}

		h, err := btf.NewHandleFromID(*prevID)
		if errors.Is(err, os.ErrNotExist) {
			// Likely a race where BTF was unloaded before we could retrieve an fd.
			continue
		}
		if err != nil {
			t.Fatal(err)
		}

		return h
	}
}
