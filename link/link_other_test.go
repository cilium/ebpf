//go:build !windows

package link

import (
	"os"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
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
