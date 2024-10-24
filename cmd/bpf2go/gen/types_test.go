//go:build !windows

package gen

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/testutils"

	"github.com/go-quicktest/qt"
)

func TestCollectGlobalTypes(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec(testutils.NativeFile(t, "../testdata/minimal-%s.elf"))
	if err != nil {
		t.Fatal(err)
	}

	map1 := spec.Maps["map1"]

	types := CollectGlobalTypes(spec)
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, qt.CmpEquals(types, []btf.Type{map1.Key, map1.Value}, typesEqualComparer))
}
