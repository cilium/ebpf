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
		Value:      &btf.Struct{Name: "bpf_struct_ops_bpf_testmod_ops"},
		Contents: []MapKV{
			{
				Key:   uint32(0),
				Value: make([]byte, 448),
			},
		},
	}

	s, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}

	target := btf.Type((*btf.Struct)(nil))
	_, module, err := findTargetInKernel(s, "bpf_struct_ops_bpf_testmod_ops", &target)
	if errors.Is(err, btf.ErrNotFound) {
		t.Skip("bpf_testmod_ops not loaded")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer module.Close()

	m, err := NewMap(ms)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatalf("creating struct_ops map failed: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
}
