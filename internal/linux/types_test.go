package linux

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"

	qt "github.com/frankban/quicktest"
)

func TestTypes(t *testing.T) {
	types, err := TypesNoCopy()
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, types, qt.Not(qt.IsNil))
}

func TestFindVMLinux(t *testing.T) {
	file, fallback, err := findVMLinuxBTF()
	if errors.Is(err, internal.ErrNotSupported) {
		t.Skip("Not supported:", err)
	}
	if err != nil {
		t.Fatal("Can't find vmlinux BTF:", err)
	}
	defer file.Close()

	if file.Name() == builtinVMLinuxBTFPath && fallback {
		t.Fatal(builtinVMLinuxBTFPath, "is classified as a fallback")
	}
}
