package testutils

import (
	"io/ioutil"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func CreateCgroup(tb testing.TB) *os.File {
	tb.Helper()

	cgdir, err := ioutil.TempDir("/sys/fs/cgroup/unified", "ebpf-link")
	if err != nil {
		tb.Fatal("Can't create cgroupv2:", err)
	}

	cgroup, err := os.Open(cgdir)
	if err != nil {
		os.Remove(cgdir)
		tb.Fatal(err)
	}
	tb.Cleanup(func() {
		cgroup.Close()
		os.Remove(cgdir)
	})

	return cgroup
}

func GetCgroupIno(t *testing.T, cgroup *os.File) uint64 {
	cgroupStat := unix.Stat_t{}
	err := unix.Fstat(int(cgroup.Fd()), &cgroupStat)
	if err != nil {
		t.Fatal(err)
	}

	return cgroupStat.Ino
}
