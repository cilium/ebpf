package ebpf

import (
	"bytes"
	"sync"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/go-quicktest/qt"
)

type specAndRawBTF struct {
	raw  []byte
	spec *btf.Spec
}

func TestFindStructOpsKernTypes(t *testing.T) {
	spec := vmlinuxTestdataSpec(t)
	kernTypes, err := findStructOpsKernTypes(spec, "bpf_dummy_ops")
	if err != nil {
		t.Fatal("failed to find struct_ops kern types", err)
	}

	qt.Assert(t, qt.Equals(kernTypes.Type.TypeName(), "bpf_dummy_ops"))
	qt.Assert(t, qt.Equals(kernTypes.ValueType.Name, "bpf_struct_ops_bpf_dummy_ops"))
	qt.Assert(t, qt.Equals(kernTypes.DataMember.Name, "data"))
}

func TestFindStructOpsMapByOffset(t *testing.T) {
	maps := map[string]*MapSpec{
		"a": {
			Name:      "a",
			Type:      Hash,
			ValueSize: 100,
		},
		"b": {
			Name:      "b",
			Type:      StructOpsMap,
			ValueSize: 382,
			SecIdx:    1,
			SecOffset: 100,
		},
	}

	ms, err := findStructOpsMapByOffset(maps, 1, 256)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(ms.Name, "b"))

	ms, err = findStructOpsMapByOffset(maps, 0, 0)
	qt.Assert(t, qt.Not(qt.IsNil(err)))
}

// helpers

var vmlinuxTestdata = sync.OnceValues(func() (specAndRawBTF, error) {
	b, err := internal.ReadAllCompressed("btf/testdata/vmlinux.btf.gz")
	if err != nil {
		return specAndRawBTF{}, err
	}

	spec, err := btf.LoadSplitSpecFromReader(bytes.NewReader(b), nil)
	if err != nil {
		return specAndRawBTF{}, err
	}

	return specAndRawBTF{b, spec}, nil
})

func vmlinuxTestdataSpec(tb testing.TB) *btf.Spec {
	tb.Helper()

	td, err := vmlinuxTestdata()
	if err != nil {
		tb.Fatal(err)
	}

	return td.spec.Copy()
}
