package testutils

import (
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

var cgroup2 = struct {
	once sync.Once
	path string
	err  error
}{}

func cgroup2Path() (string, error) {
	cgroup2.once.Do(func() {
		mounts, err := os.ReadFile("/proc/mounts")
		if err != nil {
			cgroup2.err = err
			return
		}

		for _, line := range strings.Split(string(mounts), "\n") {
			mount := strings.SplitN(line, " ", 3)
			if mount[0] == "cgroup2" {
				cgroup2.path = mount[1]
				return
			}

			continue
		}

		cgroup2.err = errors.New("cgroup2 not mounted")
	})

	if cgroup2.err != nil {
		return "", cgroup2.err
	}

	return cgroup2.path, nil
}

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
