package sys

import (
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestParseMounts(t *testing.T) {
	const mountinfo = `
8 23 0:23 / / rw,relatime - overlay overlay rw,lowerdir=/overlay:/host,upperdir=/upper,workdir=/work,uuid=on
29 28 0:27 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sys rw
30 28 0:28 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
31 28 0:6 / /dev rw,nosuid - devtmpfs devtmpfs rw,size=496012k,nr_inodes=124003,mode=755
32 31 0:29 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=000
33 29 0:7 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime - securityfs securityfs rw
34 29 0:7 / /sys/dash-dir bogus,options - bogusfs bogusfs ro,bogus=true-opt
35 29 0:30 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw,mode=700
36 29 0:30 / /sys/fs/foo\040bar\040baz rw,nosuid,nodev,noexec,relatime - bpf bpf rw,mode=700
37 29 0:30 / /sys/fs/功能\011\012\134bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw,mode=700
38 29 0:8 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime - debugfs debugfs rw
39 29 0:12 / /sys/kernel/tracing rw,nosuid,nodev,noexec,relatime - tracefs tracefs rw
`

	mounts, err := parseBPFFSMounts(strings.NewReader(mountinfo))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(mounts, 3))
	qt.Assert(t, qt.Equals(mounts[0], "/sys/fs/bpf"))
	qt.Assert(t, qt.Equals(mounts[1], "/sys/fs/foo bar baz"))
	qt.Assert(t, qt.Equals(mounts[2], "/sys/fs/功能\t\n\\bpf"))
}

func TestParseMountsSamePath(t *testing.T) {
	const mountinfo = `
48 46 0:30 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw,mode=700
58 48 0:35 / /sys/fs/bpf rw,relatime - bpf none rw,delegate_cmds=prog_load
`

	mounts, err := parseBPFFSMounts(strings.NewReader(mountinfo))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(mounts, 1))
	qt.Assert(t, qt.Equals(mounts[0], "/sys/fs/bpf"))
}

func TestParseMountsMultiple(t *testing.T) {
	const mountinfo = `
48 46 0:30 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw,mode=700
58 48 0:35 / /run/tw/bpf rw,relatime - bpf none rw,delegate_cmds=prog_load
`

	mounts, err := parseBPFFSMounts(strings.NewReader(mountinfo))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(mounts, 2))
	qt.Assert(t, qt.Equals(mounts[0], "/sys/fs/bpf"))
	qt.Assert(t, qt.Equals(mounts[1], "/run/tw/bpf"))
}

func TestParseMountsInvalid(t *testing.T) {
	const mountinfo = `48 46 0:30 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime`
	_, err := parseBPFFSMounts(strings.NewReader(mountinfo))
	qt.Assert(t, qt.IsNotNil(err))
}
