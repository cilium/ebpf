package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestCreateStructOpsMapSpecSimple(t *testing.T) {
	requireStructOpsDummy(t)

	ms := &MapSpec{
		Name:       "dummy_ops",
		Type:       StructOpsMap,
		KeySize:    4,
		ValueSize:  128,
		MaxEntries: 1,
		Contents: []MapKV{
			{
				Key: uint32(0),
				Value: structOpsMeta{
					userTypeName: "bpf_dummy_ops",
					kernTypeName: "bpf_struct_ops_bpf_dummy_ops",
				},
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
