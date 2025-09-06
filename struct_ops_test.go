package ebpf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestCreateStructOpsMapSpecSimple(t *testing.T) {
	requireTestmod(t)

	ms := &MapSpec{
		Name:       "testmod_ops",
		Type:       StructOpsMap,
		Flags:      sys.BPF_F_LINK,
		KeySize:    4,
		ValueSize:  448,
		MaxEntries: 1,
		// we use `Value` to specify a user struct type as BTF
		Value: &btf.Struct{Name: "bpf_testmod_ops"},
		Contents: []MapKV{
			{
				Key: uint32(0),
				Value: structOpsMeta{
					data:  make([]byte, 448),
					funcs: []structOpsFunc{},
				},
			},
		},
	}

	s, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, err = doFindStructTypeByName(s, "bpf_testmod_ops")
	if errors.Is(err, btf.ErrNotFound) {
		t.Skip("bpf_testmod_ops not loaded")
	}
	if err != nil {
		t.Fatal(err)
	}

	m, err := NewMap(ms)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatalf("creating struct_ops map failed: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
}
