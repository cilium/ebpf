//go:build !windows

package link

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestStructOps(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.12", "bpf_testmod_ops")

	m := mustStructOpsFixtures(t)
	l, err := AttachStructOps(StructOpsOptions{Map: m})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(l.Close()))
}

func mustStructOpsFixtures(tb testing.TB) *ebpf.Map {
	tb.Helper()

	testutils.SkipIfNotSupported(tb, haveBPFLink())

	userData := []byte{
		// test_1 func ptr (8B)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// test_2 func ptr (8B)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// data (4B) + padding (4B)
		0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00,
	}

	spec := &ebpf.CollectionSpec{
		Maps: map[string]*ebpf.MapSpec{
			"testmod_ops": {
				Name:       "testmod_ops",
				Type:       ebpf.StructOpsMap,
				MaxEntries: 1,
				Flags:      sys.BPF_F_LINK,
				Key:        &btf.Int{Size: 4},
				KeySize:    4,
				ValueSize:  24,
				Value: &btf.Struct{
					Name: "bpf_testmod_ops",
					Size: 24,
					Members: []btf.Member{
						{
							Name: "test_1",
							Type: &btf.Pointer{
								Target: &btf.FuncProto{
									Params: []btf.FuncParam{},
									Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}}},
							Offset: 0,
						},
						{
							Name: "test_2",
							Type: &btf.Pointer{
								Target: &btf.FuncProto{
									Params: []btf.FuncParam{
										{Type: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}},
										{Type: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}},
									},
									Return: (*btf.Void)(nil),
								},
							},
							Offset: 64,
						},
						{
							Name:   "data",
							Type:   &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed},
							Offset: 128, // bits
						},
					},
				},
				Contents: []ebpf.MapKV{
					{
						Key:   uint32(0),
						Value: userData,
					},
				},
			},
		},
		Programs: map[string]*ebpf.ProgramSpec{
			"test_1": {
				Name:        "test_1",
				Type:        ebpf.StructOps,
				AttachTo:    "bpf_testmod_ops:test_1",
				License:     "GPL",
				SectionName: "struct_ops/test_1",
				Instructions: asm.Instructions{
					asm.Mov.Imm(asm.R0, 0),
					asm.Return(),
				},
			},
		},
		Variables: map[string]*ebpf.VariableSpec{},
	}

	coll, err := ebpf.NewCollection(spec)
	testutils.SkipIfNotSupported(tb, err)
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() {
		coll.Close()
	})

	m := coll.Maps["testmod_ops"]
	qt.Assert(tb, qt.IsNotNil(m))

	return m
}
