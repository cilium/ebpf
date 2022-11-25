package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestQueryPrograms(t *testing.T) {
	cgroup, prog := mustCgroupFixtures(t)

	link, err := newProgAttachCgroup(cgroup, ebpf.AttachCGroupInetEgress, prog, 0)
	if err != nil {
		t.Fatal("Can't create link:", err)
	}
	defer link.Close()

	opts := QueryOptions{
		Path:       cgroup.Name(),
		AttachType: ebpf.AttachCGroupInetEgress,
	}

	ids, err := QueryPrograms(opts)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't query programs:", err)
	}

	progInfo, err := prog.Info()
	if err != nil {
		t.Fatal("Can't get program info:", err)
	}

	progId, ok := progInfo.ID()
	if !ok {
		t.Skip("Program ID not supported")
	}

	for _, id := range ids {
		if id == progId {
			return
		}
	}
	t.Fatal("Can't find program ID in query")
}
