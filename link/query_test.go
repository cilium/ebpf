package link

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"

	qt "github.com/frankban/quicktest"
	"golang.org/x/exp/slices"
)

func TestQueryPrograms(t *testing.T) {
	for name, fn := range map[string]func(*testing.T) (*ebpf.Program, Link, QueryOptions){
		"cgroup":      queryCgroupProgAttachFixtures,
		"cgroup link": queryCgroupLinkFixtures,
		"netns":       queryNetNSFixtures,
		"tcx":         queryTCXFixtures,
	} {
		t.Run(name, func(t *testing.T) {
			prog, link, opts := fn(t)
			result, err := QueryPrograms(opts)
			testutils.SkipIfNotSupported(t, err)
			qt.Assert(t, err, qt.IsNil)

			progInfo, err := prog.Info()
			qt.Assert(t, err, qt.IsNil)
			progID, _ := progInfo.ID()

			i := slices.IndexFunc(result.Programs, func(ap AttachedProgram) bool {
				return ap.ID == progID
			})
			qt.Assert(t, i, qt.Not(qt.Equals), -1)

			if name == "tcx" {
				qt.Assert(t, result.Revision, qt.Not(qt.Equals), uint64(0))
			}

			if result.HaveLinkInfo() {
				ap := result.Programs[i]
				linkInfo, err := link.Info()
				qt.Assert(t, err, qt.IsNil)

				linkID, ok := ap.LinkID()
				qt.Assert(t, ok, qt.IsTrue)
				qt.Assert(t, linkID, qt.Equals, linkInfo.ID)
			}
		})
	}
}

func queryCgroupProgAttachFixtures(t *testing.T) (*ebpf.Program, Link, QueryOptions) {
	cgroup, prog := mustCgroupFixtures(t)

	link, err := newProgAttachCgroup(cgroup, ebpf.AttachCGroupInetEgress, prog, flagAllowOverride)
	if err != nil {
		t.Fatal("Can't create link:", err)
	}
	t.Cleanup(func() {
		qt.Assert(t, link.Close(), qt.IsNil)
	})

	return prog, nil, QueryOptions{
		Target: int(cgroup.Fd()),
		Attach: ebpf.AttachCGroupInetEgress,
	}
}

func queryCgroupLinkFixtures(t *testing.T) (*ebpf.Program, Link, QueryOptions) {
	cgroup, prog := mustCgroupFixtures(t)

	link, err := newLinkCgroup(cgroup, ebpf.AttachCGroupInetEgress, prog)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create link:", err)
	}
	t.Cleanup(func() {
		qt.Assert(t, link.Close(), qt.IsNil)
	})

	return prog, nil, QueryOptions{
		Target: int(cgroup.Fd()),
		Attach: ebpf.AttachCGroupInetEgress,
	}
}

func queryNetNSFixtures(t *testing.T) (*ebpf.Program, Link, QueryOptions) {
	testutils.SkipOnOldKernel(t, "4.20", "flow_dissector program")

	prog := mustLoadProgram(t, ebpf.FlowDissector, ebpf.AttachFlowDissector, "")

	// RawAttachProgramOptions.Target needs to be 0, as PROG_ATTACH with namespaces
	// only works with the threads current netns. Any other fd will be rejected.
	if err := RawAttachProgram(RawAttachProgramOptions{
		Target:  0,
		Program: prog,
		Attach:  ebpf.AttachFlowDissector,
	}); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		err := RawDetachProgram(RawDetachProgramOptions{
			Target:  0,
			Program: prog,
			Attach:  ebpf.AttachFlowDissector,
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	netns, err := os.Open("/proc/self/ns/net")
	qt.Assert(t, err, qt.IsNil)
	t.Cleanup(func() { netns.Close() })

	return prog, nil, QueryOptions{
		Target: int(netns.Fd()),
		Attach: ebpf.AttachFlowDissector,
	}
}

func queryTCXFixtures(t *testing.T) (*ebpf.Program, Link, QueryOptions) {
	testutils.SkipOnOldKernel(t, "6.6", "TCX link")

	prog := mustLoadProgram(t, ebpf.SchedCLS, ebpf.AttachTCXIngress, "")

	link, iface := mustAttachTCX(t, prog, ebpf.AttachTCXIngress)

	return prog, link, QueryOptions{
		Target: iface,
		Attach: ebpf.AttachTCXIngress,
	}
}
