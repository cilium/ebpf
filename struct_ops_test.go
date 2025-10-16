package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestCreateStructOpsMapSpecSimple(t *testing.T) {
	requireTestmodOps(t)

	ms := &MapSpec{
		Name:       "testmod_ops",
		Type:       StructOpsMap,
		Flags:      sys.BPF_F_LINK,
		Key:        &btf.Int{Size: 4},
		KeySize:    4,
		Value:      &btf.Struct{Name: "bpf_testmod_ops"},
		MaxEntries: 1,
		Contents: []MapKV{
			{
				Key:   uint32(0),
				Value: make([]byte, 448),
			},
		},
	}

	m, err := NewMap(ms)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatalf("creating struct_ops map failed: %v", err)
	}
	t.Cleanup(func() { _ = m.Close() })
}
