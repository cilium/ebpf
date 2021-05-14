package link

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
	qt "github.com/frankban/quicktest"
)

func TestTraceEventTypePMU(t *testing.T) {
	// Requires at least 4.17 (e12f03d7031a "perf/core: Implement the 'perf_kprobe' PMU")
	testutils.SkipOnOldKernel(t, "4.17", "perf_kprobe PMU")

	c := qt.New(t)

	et, err := getPMUEventType(kprobeType)
	c.Assert(err, qt.IsNil)
	c.Assert(et, qt.Not(qt.Equals), 0)

	et, err = getPMUEventType(uprobeType)
	c.Assert(err, qt.IsNil)
	c.Assert(et, qt.Not(qt.Equals), 0)
}

func TestTraceEventID(t *testing.T) {
	c := qt.New(t)

	eid, err := getTraceEventID("syscalls", "sys_enter_execve")
	c.Assert(err, qt.IsNil)
	c.Assert(eid, qt.Not(qt.Equals), 0)
}

func TestTraceReadID(t *testing.T) {
	_, err := uint64FromFile("/base/path/", "../escaped")
	if !errors.Is(err, errInvalidInput) {
		t.Errorf("expected error %s, got: %s", errInvalidInput, err)
	}

	_, err = uint64FromFile("/base/path/not", "../not/escaped")
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected os.ErrNotExist, got: %s", err)
	}
}

func TestTraceEventRegex(t *testing.T) {
	var tests = []struct {
		name string
		in   string
		fail bool
	}{
		{"empty string", "", true},
		{"leading number", "1test", true},
		{"underscore first", "__x64_syscall", false},
		{"contains number", "bpf_trace_run1", false},
		{"underscore", "_", false},
		{"contains dash", "-EINVAL", true},
		{"contains number", "all0wed", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exp := "pass"
			if tt.fail {
				exp = "fail"
			}

			if rgxTraceEvent.MatchString(tt.in) == tt.fail {
				t.Errorf("expected string '%s' to %s regex match", tt.in, exp)
			}
		})
	}
}
