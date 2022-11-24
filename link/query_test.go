package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestQueryPrograms(t *testing.T) {
	for name, fn := range map[string]func(*testing.T) (*ebpf.Program, QueryOptions){
		"cgroup": queryCgroupFixtures,
		"netns":  queryNetNSFixtures,
	} {
		t.Run(name, func(t *testing.T) {
			prog, opts := fn(t)
			ids, err := QueryPrograms(opts)
			testutils.SkipIfNotSupported(t, err)
			if err != nil {
				t.Fatal("Can't query programs:", err)
			}

			progInfo, err := prog.Info()
			if err != nil {
				t.Fatal("Can't get program info:", err)
			}

			progId, _ := progInfo.ID()

			for _, id := range ids {
				if id == progId {
					return
				}
			}
			t.Fatalf("Can't find program ID %d in query result: %v", progId, ids)
		})
	}
}

func queryCgroupFixtures(t *testing.T) (*ebpf.Program, QueryOptions) {
	cgroup, prog := mustCgroupFixtures(t)

	link, err := newProgAttachCgroup(cgroup, ebpf.AttachCGroupInetEgress, prog, 0)
	if err != nil {
		t.Fatal("Can't create link:", err)
	}
	t.Cleanup(func() {
		link.Close()
	})

	return prog, QueryOptions{Path: cgroup.Name(), Attach: ebpf.AttachCGroupInetEgress}
}

func queryNetNSFixtures(t *testing.T) (*ebpf.Program, QueryOptions) {
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

	return prog, QueryOptions{Path: "/proc/self/ns/net", Attach: ebpf.AttachFlowDissector}
}
