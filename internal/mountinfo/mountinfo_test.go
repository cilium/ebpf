package mountinfo

import (
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestParseEntriesPreservesRoot(t *testing.T) {
	// Subdirectory bind mounts retain their original fstype but expose a non-/
	// root field, so callers can distinguish them from full filesystem mounts.
	const mountinfo = `
39 29 0:12 / /sys/kernel/tracing rw - tracefs tracefs rw
40 29 0:12 /events /weird/tracing-events rw - tracefs tracefs rw
`

	entries, err := parseEntries(strings.NewReader(mountinfo))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(entries, 2))
	qt.Assert(t, qt.Equals(entries[0].Root, "/"))
	qt.Assert(t, qt.Equals(entries[1].Root, "/events"))
}

func TestParseEntriesLongLine(t *testing.T) {
	// Overlay lowerdir lists in containers commonly exceed bufio.Scanner's
	// default 64 KiB token limit. Build a synthetic line just over that
	// threshold and assert that parsing succeeds and surfaces the entry.
	var lowers []string
	for range 1000 {
		lowers = append(lowers, "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/12345/fs")
	}
	long := "8 23 0:23 / / rw,relatime - overlay overlay rw,lowerdir=" + strings.Join(lowers, ":")
	if len(long) <= 64*1024 {
		t.Fatalf("test fixture not long enough: %d bytes", len(long))
	}
	mountinfo := long + "\n39 29 0:12 / /sys/kernel/tracing rw - tracefs tracefs rw\n"

	entries, err := parseEntries(strings.NewReader(mountinfo))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(entries, 2))
	qt.Assert(t, qt.Equals(entries[0].FSType, "overlay"))
	qt.Assert(t, qt.Equals(entries[1].MountPoint, "/sys/kernel/tracing"))
	qt.Assert(t, qt.Equals(entries[1].FSType, "tracefs"))
}

func TestParseEntries(t *testing.T) {
	const mountinfo = `
8 23 0:23 / / rw,relatime - overlay overlay rw,lowerdir=/overlay:/host,upperdir=/upper,workdir=/work,uuid=on
29 28 0:27 / /sys rw,nosuid,nodev,noexec,relatime - sysfs sys rw
30 28 0:28 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
35 29 0:30 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw,mode=700
36 29 0:30 / /sys/fs/foo\040bar\040baz rw,nosuid,nodev,noexec,relatime - bpf bpf rw,mode=700
37 29 0:30 / /sys/fs/功能\011\012\134bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw,mode=700
38 29 0:8 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime - debugfs debugfs rw
39 29 0:12 / /sys/kernel/tracing rw,nosuid,nodev,noexec,relatime - tracefs tracefs rw
`

	entries, err := parseEntries(strings.NewReader(mountinfo))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(entries, 8))

	qt.Assert(t, qt.Equals(entries[0].MountPoint, "/"))
	qt.Assert(t, qt.Equals(entries[0].FSType, "overlay"))

	qt.Assert(t, qt.Equals(entries[3].MountPoint, "/sys/fs/bpf"))
	qt.Assert(t, qt.Equals(entries[3].FSType, "bpf"))

	// Octal escapes for space, tab, newline, backslash.
	qt.Assert(t, qt.Equals(entries[4].MountPoint, "/sys/fs/foo bar baz"))
	qt.Assert(t, qt.Equals(entries[5].MountPoint, "/sys/fs/功能\t\n\\bpf"))

	qt.Assert(t, qt.Equals(entries[6].MountPoint, "/sys/kernel/debug"))
	qt.Assert(t, qt.Equals(entries[6].FSType, "debugfs"))

	qt.Assert(t, qt.Equals(entries[7].MountPoint, "/sys/kernel/tracing"))
	qt.Assert(t, qt.Equals(entries[7].FSType, "tracefs"))
}

func TestParseEntriesInvalid(t *testing.T) {
	t.Run("missing dash separator", func(t *testing.T) {
		const mountinfo = `48 46 0:30 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime`
		_, err := parseEntries(strings.NewReader(mountinfo))
		qt.Assert(t, qt.IsNotNil(err))
	})

	t.Run("too few fields before dash", func(t *testing.T) {
		const mountinfo = `48 46 0:30 / /sys/fs/bpf - bpf bpf rw`
		_, err := parseEntries(strings.NewReader(mountinfo))
		qt.Assert(t, qt.IsNotNil(err))
	})

	t.Run("missing fstype after dash", func(t *testing.T) {
		const mountinfo = `48 46 0:30 / /sys/fs/bpf rw,nosuid - `
		_, err := parseEntries(strings.NewReader(mountinfo))
		qt.Assert(t, qt.IsNotNil(err))
	})
}

func TestFindByFSType(t *testing.T) {
	const mountinfo = `
35 29 0:30 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime - bpf bpf rw,mode=700
36 29 0:30 / /sys/fs/bpf rw,relatime - bpf none rw,delegate_cmds=prog_load
37 29 0:30 / /run/tw/bpf rw,relatime - bpf none rw,delegate_cmds=prog_load
38 29 0:8 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime - debugfs debugfs rw
39 29 0:12 / /sys/kernel/tracing rw,nosuid,nodev,noexec,relatime - tracefs tracefs rw
40 29 0:13 / /custom/tracing rw - tracefs tracefs rw
`

	entries, err := parseEntries(strings.NewReader(mountinfo))
	qt.Assert(t, qt.IsNil(err))

	t.Run("filters and dedupes by mount point", func(t *testing.T) {
		got := filterByFSType(entries, "bpf")
		qt.Assert(t, qt.DeepEquals(got, []string{"/sys/fs/bpf", "/run/tw/bpf"}))
	})

	t.Run("returns all matching mount points in order", func(t *testing.T) {
		got := filterByFSType(entries, "tracefs")
		qt.Assert(t, qt.DeepEquals(got, []string{"/sys/kernel/tracing", "/custom/tracing"}))
	})

	t.Run("single match", func(t *testing.T) {
		got := filterByFSType(entries, "debugfs")
		qt.Assert(t, qt.DeepEquals(got, []string{"/sys/kernel/debug"}))
	})

	t.Run("no match returns empty", func(t *testing.T) {
		got := filterByFSType(entries, "nfs")
		qt.Assert(t, qt.HasLen(got, 0))
	})
}
