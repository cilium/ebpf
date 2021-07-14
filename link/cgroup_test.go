package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"

	"golang.org/x/sys/unix"
)

type BpfCgroupStorageKey struct {
	CgroupInodeId uint64
	AttachType    ebpf.AttachType
	_             [4]byte // Padding
}

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

func TestCgroupPerCPUStorageMarshaling(t *testing.T) {
	numCPU, err := internal.PossibleCPUs()
	if err != nil {
		t.Fatal(err)
	}
	if numCPU < 2 {
		t.Skip("Test requires at least two CPUs")
	}
	testutils.SkipOnOldKernel(t, "4.20", "per-CPU CGoup storage")

	arr, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:      ebpf.PerCPUCGroupStorage,
		KeySize:   16,
		ValueSize: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer arr.Close()

	prog := mustCgroupEgressProgramWithMap(t, arr)
	cgroup := mustCgroupFixturesWithProgram(t, prog)

	link, err := AttachCgroup(CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: prog,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer link.Close()

	cgroupStat := unix.Stat_t{}
	err = unix.Fstat(int(cgroup.Fd()), &cgroupStat)
	if err != nil {
		t.Fatal(err)
	}

	var mapKey = &BpfCgroupStorageKey{
		CgroupInodeId: cgroupStat.Ino,
		AttachType:    ebpf.AttachCGroupInetEgress,
	}

	values := []uint64{1, 2}
	if err := arr.Put(mapKey, values); err != nil {
		t.Fatal(err)
	}

	var retrieved []uint64
	if err := arr.Lookup(mapKey, &retrieved); err != nil {
		t.Fatalf("Can't retrieve cgroup %s storage: %s", cgroup.Name(), err)
	}

	for i, want := range []uint64{1, 2} {
		if retrieved[i] == 0 {
			t.Error("First item is 0")
		} else if have := retrieved[i]; have != want {
			t.Errorf("PerCPUCGroupStorage map is not correctly unmarshaled, expected %d but got %d", want, have)
		}
	}
}
