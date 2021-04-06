package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestAttachCgroup(t *testing.T) {
	cgroup, prog := mustCgroupFixtures(t)

	link, err := AttachCgroup(CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: prog,
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	if haveBPFLink() == nil {
		if _, ok := link.(*linkCgroup); !ok {
			t.Fatalf("Have support for bpf_link, but got %T instead of linkCgroup", link)
		}
	} else {
		if _, ok := link.(*progAttachCgroup); !ok {
			t.Fatalf("Expected progAttachCgroup, got %T instead", link)
		}
	}
}

func TestProgAttachCgroup(t *testing.T) {
	cgroup, prog := mustCgroupFixtures(t)

	link, err := newProgAttachCgroup(cgroup, ebpf.AttachCGroupInetEgress, prog, 0)
	if err != nil {
		t.Fatal("Can't create link:", err)
	}

	testLink(t, link, testLinkOptions{
		prog: prog,
	})
}

func TestProgAttachCgroupAllowMulti(t *testing.T) {
	cgroup, prog := mustCgroupFixtures(t)

	link, err := newProgAttachCgroup(cgroup, ebpf.AttachCGroupInetEgress, prog, flagAllowMulti)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create link:", err)
	}

	// It's currently not possible for a program to replace
	// itself.
	prog2 := mustCgroupEgressProgram(t)
	testLink(t, link, testLinkOptions{
		prog: prog2,
	})
}

func TestLinkCgroup(t *testing.T) {
	cgroup, prog := mustCgroupFixtures(t)

	link, err := newLinkCgroup(cgroup, ebpf.AttachCGroupInetEgress, prog)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create link:", err)
	}

	testLink(t, link, testLinkOptions{
		prog:       prog,
		loadPinned: LoadPinnedCgroup,
	})
}
