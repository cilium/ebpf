package testutils

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

var cgroup2Path = internal.Memoize(func() (string, error) {
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return "", err
	}

	for _, line := range strings.Split(string(mounts), "\n") {
		mount := strings.SplitN(line, " ", 3)
		if mount[0] == "cgroup2" {
			return mount[1], nil
		}

		continue
	}

	return "", errors.New("cgroup2 not mounted")
})

func CreateCgroup(tb testing.TB) *os.File {
	tb.Helper()

	cg2, err := cgroup2Path()
	if err != nil {
		tb.Fatal("Can't locate cgroup2 mount:", err)
	}

	cgdir, err := os.MkdirTemp(cg2, "ebpf-link")
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
