package link

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
	qt "github.com/frankban/quicktest"
)

func TestTraceEventTypePMU(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.17", "perf_kprobe PMU")

	c := qt.New(t)

	et, err := getPMUEventType("kprobe")
	c.Assert(err, qt.IsNil)
	c.Assert(et, qt.Not(qt.Equals), 0)
}

func TestTraceEventID(t *testing.T) {
	c := qt.New(t)

	eid, err := getTraceEventID("syscalls", "sys_enter_fork")
	c.Assert(err, qt.IsNil)
	c.Assert(eid, qt.Not(qt.Equals), 0)
}

func TestTraceReadID(t *testing.T) {
	_, err := uint64FromFile("/base/path/", "../escaped")
	if !errors.Is(err, ErrInvalidInput) {
		t.Errorf("expected error %s, got: %s", ErrInvalidInput, err)
	}

	_, err = uint64FromFile("/base/path/not", "../not/escaped")
	if !errors.Is(err, ErrNotSupported) {
		t.Errorf("expected error %s, got: %s", ErrNotSupported, err)
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

func TestTraceEventClose(t *testing.T) {
	c := qt.New(t)

	var te TraceEvent
	c.Assert(te.Close(), qt.ErrorMatches, ".* empty trace event")

	te = TraceEvent{group: "foo", name: "bar", progType: ebpf.UnspecifiedProgram}
	c.Assert(te.Close(), qt.ErrorMatches, "unknown program type .*")
}
