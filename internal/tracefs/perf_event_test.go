package tracefs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal/mountinfo"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestEventID(t *testing.T) {
	eid, err := EventID("syscalls", "sys_enter_mmap")
	testutils.SkipIfNotSupportedOnOS(t, err)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Not(qt.Equals(eid, 0)))
}

func TestSanitizePath(t *testing.T) {
	_, err := sanitizeTracefsPath("../escaped")
	testutils.SkipIfNotSupportedOnOS(t, err)
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected error %s, got: %s", ErrInvalidInput, err)
	}

	_, err = sanitizeTracefsPath("./not/escaped")
	if err != nil {
		t.Errorf("expected no error, got: %s", err)
	}
}

func TestValidIdentifier(t *testing.T) {
	tests := []struct {
		name string
		in   string
		fail bool
	}{
		{"empty string", "", true},
		{"leading number", "1test", true},
		{"underscore first", "__x64_syscall", false},
		{"contains number", "bpf_trace_run1", false},
		{"underscore", "_", false},
		{"leading dash", "-EINVAL", true},
		{"contains number", "all0wed", false},
		{"contains dash", "trace-group", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exp := "pass"
			if tt.fail {
				exp = "fail"
			}

			if validIdentifier(tt.in) == tt.fail {
				t.Errorf("expected string '%s' to %s valid ID check", tt.in, exp)
			}
		})
	}
}

func TestSanitizeIdentifier(t *testing.T) {
	tests := []struct {
		symbol   string
		expected string
	}{
		{"readline", "readline"},
		{"main.Func123", "main_Func123"},
		{"a.....a", "a_a"},
		{"./;'{}[]a", "_a"},
		{"***xx**xx###", "_xx_xx_"},
		{`@P#r$i%v^3*+t)i&k++--`, "_P_r_i_v_3_t_i_k_"},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			sanitized := sanitizeIdentifier(tt.symbol)
			if tt.expected != sanitized {
				t.Errorf("Expected sanitized symbol to be '%s', got '%s'", tt.expected, sanitized)
			}
		})
	}
}

func TestGetTracefsPath(t *testing.T) {
	path, err := getTracefsPath()
	testutils.SkipIfNotSupportedOnOS(t, err)
	qt.Assert(t, qt.IsNil(err))
	_, err = os.Stat(path)
	qt.Assert(t, qt.IsNil(err))
}

func TestFindTracefsInEntries(t *testing.T) {
	tmpDebugWithTracing := t.TempDir()
	qt.Assert(t, qt.IsNil(os.Mkdir(filepath.Join(tmpDebugWithTracing, "tracing"), 0o755)))
	tmpDebugBare := t.TempDir()

	t.Run("tracefs entry returns its mount point", func(t *testing.T) {
		got := findTracefsInEntries([]mountinfo.Entry{
			{MountPoint: "/host/sys/kernel/tracing", Root: "/", FSType: "tracefs"},
		})
		qt.Assert(t, qt.Equals(got, "/host/sys/kernel/tracing"))
	})

	t.Run("first tracefs entry wins when multiple", func(t *testing.T) {
		got := findTracefsInEntries([]mountinfo.Entry{
			{MountPoint: "/sys/kernel/tracing", Root: "/", FSType: "tracefs"},
			{MountPoint: "/host/sys/kernel/tracing", Root: "/", FSType: "tracefs"},
		})
		qt.Assert(t, qt.Equals(got, "/sys/kernel/tracing"))
	})

	t.Run("tracefs preferred over debugfs", func(t *testing.T) {
		got := findTracefsInEntries([]mountinfo.Entry{
			{MountPoint: tmpDebugWithTracing, Root: "/", FSType: "debugfs"},
			{MountPoint: "/sys/kernel/tracing", Root: "/", FSType: "tracefs"},
		})
		qt.Assert(t, qt.Equals(got, "/sys/kernel/tracing"))
	})

	t.Run("debugfs entry with tracing subdir returns the subdir", func(t *testing.T) {
		got := findTracefsInEntries([]mountinfo.Entry{
			{MountPoint: tmpDebugWithTracing, Root: "/", FSType: "debugfs"},
		})
		qt.Assert(t, qt.Equals(got, filepath.Join(tmpDebugWithTracing, "tracing")))
	})

	t.Run("debugfs entry without tracing subdir falls through", func(t *testing.T) {
		got := findTracefsInEntries([]mountinfo.Entry{
			{MountPoint: tmpDebugBare, Root: "/", FSType: "debugfs"},
		})
		qt.Assert(t, qt.Equals(got, ""))
	})

	t.Run("no tracefs and no usable debugfs returns empty", func(t *testing.T) {
		got := findTracefsInEntries([]mountinfo.Entry{
			{MountPoint: "/", Root: "/", FSType: "overlay"},
			{MountPoint: "/proc", Root: "/", FSType: "proc"},
		})
		qt.Assert(t, qt.Equals(got, ""))
	})

	t.Run("nil entries returns empty", func(t *testing.T) {
		got := findTracefsInEntries(nil)
		qt.Assert(t, qt.Equals(got, ""))
	})

	t.Run("subdirectory bind mount is skipped in favor of real tracefs", func(t *testing.T) {
		// /weird/tracing-events is a bind mount of tracefs's events/ subdir;
		// it should not be picked even though it appears first.
		got := findTracefsInEntries([]mountinfo.Entry{
			{MountPoint: "/weird/tracing-events", Root: "/events", FSType: "tracefs"},
			{MountPoint: "/sys/kernel/tracing", Root: "/", FSType: "tracefs"},
		})
		qt.Assert(t, qt.Equals(got, "/sys/kernel/tracing"))
	})

	t.Run("only subdirectory tracefs mounts means no usable tracefs", func(t *testing.T) {
		got := findTracefsInEntries([]mountinfo.Entry{
			{MountPoint: "/weird/tracing-events", Root: "/events", FSType: "tracefs"},
		})
		qt.Assert(t, qt.Equals(got, ""))
	})

	t.Run("subdirectory debugfs bind mount is skipped", func(t *testing.T) {
		got := findTracefsInEntries([]mountinfo.Entry{
			{MountPoint: tmpDebugWithTracing, Root: "/tracing", FSType: "debugfs"},
		})
		qt.Assert(t, qt.Equals(got, ""))
	})
}
