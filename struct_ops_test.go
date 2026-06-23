package ebpf

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestCreateStructOpsMapSpecSimple(t *testing.T) {
	requireTestmodOps(t)

	btfSpec, err := btf.LoadKernelModuleSpec("bpf_testmod")
	qt.Assert(t, qt.IsNil(err))

	var outerValueType *btf.Struct
	qt.Assert(t, qt.IsNil(btfSpec.TypeByName(structOpsValuePrefix+"bpf_testmod_ops", &outerValueType)))

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
				Value: make([]byte, outerValueType.Size),
			},
		},
	}

	m, err := NewMap(ms)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(func() { _ = m.Close() })
}
