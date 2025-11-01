//go:build !windows

package link

import (
	"os"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
)

func testLinkArch(t *testing.T, link Link) {
	t.Run("link/info", func(t *testing.T) {
		info, err := link.Info()
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal("Link info returns an error:", err)
		}

		if info.Type == 0 {
			t.Fatal("Failed to get link info type")
		}

		switch link.(type) {
		case *tracing:
			if info.Tracing() == nil {
				t.Fatalf("Failed to get link tracing extra info")
			}
		case *linkCgroup:
			cg := info.Cgroup()
			if cg.CgroupId == 0 {
				t.Fatalf("Failed to get link Cgroup extra info")
			}
		case *NetNsLink:
			netns := info.NetNs()
			if netns.AttachType == 0 {
				t.Fatalf("Failed to get link NetNs extra info")
			}
		case *xdpLink:
			xdp := info.XDP()
			if xdp.Ifindex == 0 {
				t.Fatalf("Failed to get link XDP extra info")
			}
		case *tcxLink:
			tcx := info.TCX()
			if tcx.Ifindex == 0 {
				t.Fatalf("Failed to get link TCX extra info")
			}
		case *netfilterLink:
			nf := info.Netfilter()
			if nf.Priority == 0 {
				t.Fatalf("Failed to get link Netfilter extra info")
			}
		case *kprobeMultiLink:
			// test default Info data
			kmulti := info.KprobeMulti()
			if count, ok := kmulti.AddressCount(); ok {
				qt.Assert(t, qt.Not(qt.Equals(count, 0)))

				_, ok = kmulti.Missed()
				qt.Assert(t, qt.IsTrue(ok))
				// NB: We don't check that missed is actually correct
				// since it's not easy to trigger from tests.
			}
		case *perfEventLink:
			// test default Info data
			pevent := info.PerfEvent()
			switch pevent.Type {
			case sys.BPF_PERF_EVENT_KPROBE, sys.BPF_PERF_EVENT_KRETPROBE:
				kp := pevent.Kprobe()
				if addr, ok := kp.Address(); ok {
					qt.Assert(t, qt.Not(qt.Equals(addr, 0)))

					_, ok := kp.Missed()
					qt.Assert(t, qt.IsTrue(ok))
					// NB: We don't check that missed is actually correct
					// since it's not easy to trigger from tests.
				}
			}
		}
	})
}

func newRawLink(t *testing.T) (*RawLink, *ebpf.Program) {
	t.Helper()

	cgroup, prog := mustCgroupFixtures(t)
	link, err := AttachRawLink(RawLinkOptions{
		Target:  int(cgroup.Fd()),
		Program: prog,
		Attach:  ebpf.AttachCGroupInetEgress,
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create raw link:", err)
	}
	t.Cleanup(func() { link.Close() })

	return link, prog
}

func mustCgroupFixtures(t *testing.T) (*os.File, *ebpf.Program) {
	t.Helper()

	testutils.SkipIfNotSupported(t, haveProgAttach())

	return testutils.CreateCgroup(t), mustLoadProgram(t, ebpf.CGroupSKB, 0, "")
}

func mustStructOpsFixtures(t *testing.T) (*ebpf.Collection, error) {
	t.Helper()

	testutils.SkipIfNotSupported(t, haveBPFLink())

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

	return ebpf.NewCollection(spec)
}

func mustLoadProgram(tb testing.TB, typ ebpf.ProgramType, attachType ebpf.AttachType, attachTo string) *ebpf.Program {
	tb.Helper()

	license := "MIT"
	switch typ {
	case ebpf.RawTracepoint, ebpf.LSM:
		license = "GPL"
	}

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       typ,
		AttachType: attachType,
		AttachTo:   attachTo,
		License:    license,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		prog.Close()
	})

	return prog
}

func TestDetachLinkFail(t *testing.T) {
	prog := mustLoadProgram(t, ebpf.Kprobe, 0, "")
	defer prog.Close()

	uprobeLink, err := bashEx.Uprobe(bashSym, prog, nil)
	qt.Assert(t, qt.IsNil(err))
	defer uprobeLink.Close()

	err = uprobeLink.Detach()
	qt.Assert(t, qt.ErrorIs(err, ErrNotSupported), qt.Commentf("got error: %s", err))
}
