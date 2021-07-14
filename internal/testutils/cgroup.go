package testutils

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// MustCgroupFixtures attaches a dummy eBPF egress program with a perècpu storage map to a temporary cgroup
func MustCgroupFixtures(t *testing.T) (*os.File, *ebpf.Map) {
	t.Helper()

	cgdir, err := ioutil.TempDir("/sys/fs/cgroup/unified", "ebpf-link")
	if err != nil {
		t.Fatal("Can't create cgroupv2:", err)
	}

	cgroup, err := os.Open(cgdir)
	if err != nil {
		os.Remove(cgdir)
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cgroup.Close()
		os.Remove(cgdir)
	})

	arr, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:      ebpf.PerCPUCGroupStorage,
		KeySize:   16,
		ValueSize: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		arr.Close()
	})

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
	t.Cleanup(func() {
		prog.Close()
	})

	cgroupLink, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroup.Name(),
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: prog,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cgroupLink.Close()
	})

	return cgroup, arr
}

func GetCgroupIno(t *testing.T, cgroup *os.File) uint64 {
	cgroupStat := unix.Stat_t{}
	err := unix.Fstat(int(cgroup.Fd()), &cgroupStat)
	if err != nil {
		t.Fatal(err)
	}

	return cgroupStat.Ino
}
