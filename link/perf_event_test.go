package link

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
	qt "github.com/frankban/quicktest"
)

func TestTraceEventID(t *testing.T) {
	c := qt.New(t)

	eid, err := getTraceEventID("syscalls", "sys_enter_mmap")
	c.Assert(err, qt.IsNil)
	c.Assert(eid, qt.Not(qt.Equals), 0)
}

func TestSanitizePath(t *testing.T) {
	_, err := sanitizeTracefsPath("../escaped")
	if !errors.Is(err, errInvalidInput) {
		t.Errorf("expected error %s, got: %s", errInvalidInput, err)
	}

	_, err = sanitizeTracefsPath("./not/escaped")
	if err != nil {
		t.Errorf("expected no error, got: %s", err)
	}
}

func TestTraceValidID(t *testing.T) {
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
		{"contains dash", "-EINVAL", true},
		{"contains number", "all0wed", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exp := "pass"
			if tt.fail {
				exp = "fail"
			}

			if isValidTraceID(tt.in) == tt.fail {
				t.Errorf("expected string '%s' to %s valid ID check", tt.in, exp)
			}
		})
	}
}

func TestGetTracefsPath(t *testing.T) {
	_, err := getTracefsPath()
	qt.Assert(t, err, qt.IsNil)
}

func TestHaveBPFLinkPerfEvent(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBPFLinkPerfEvent)
}
