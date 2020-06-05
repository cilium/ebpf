package link

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestAttachCgroup(t *testing.T) {
	cgroup, prog, cleanup := mustCgroupFixtures(t)
	defer cleanup()

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
	cgroup, prog, cleanup := mustCgroupFixtures(t)
	defer cleanup()

	link, err := newProgAttachCgroup(cgroup, ebpf.AttachCGroupInetEgress, prog, 0)
	if err != nil {
		t.Fatal("Can't create link:", err)
	}

	testLink(t, link, testLinkOptions{
		prog: prog,
	})
}

func TestProgAttachCgroupAllowMulti(t *testing.T) {
	cgroup, prog, cleanup := mustCgroupFixtures(t)
	defer cleanup()

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
	cgroup, prog, cleanup := mustCgroupFixtures(t)
	defer cleanup()

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

func mustCgroupFixtures(t *testing.T) (*os.File, *ebpf.Program, func()) {
	t.Helper()

	testutils.SkipIfNotSupported(t, haveProgAttach())

	prog := mustCgroupEgressProgram(t)
	cgdir, err := ioutil.TempDir("/sys/fs/cgroup/unified", "ebpf-link")
	if err != nil {
		prog.Close()
		t.Fatal("Can't create cgroupv2:", err)
	}

	cgroup, err := os.Open(cgdir)
	if err != nil {
		prog.Close()
		os.Remove(cgdir)
		t.Fatal(err)
	}

	return cgroup, prog, func() {
		prog.Close()
		cgroup.Close()
		os.Remove(cgdir)
	}
}

func mustCgroupEgressProgram(t *testing.T) *ebpf.Program {
	t.Helper()

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.CGroupSKB,
		AttachType: ebpf.AttachCGroupInetEgress,
		License:    "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return prog
}
