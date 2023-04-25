package tracefs

import (
	"errors"
	"fmt"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestEventID(t *testing.T) {
	c := qt.New(t)

	eid, err := EventID("syscalls", "sys_enter_mmap")
	c.Assert(err, qt.IsNil)
	c.Assert(eid, qt.Not(qt.Equals), 0)
}

func TestSanitizePath(t *testing.T) {
	_, err := sanitizeTracefsPath("../escaped")
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
		{"contains dash", "-EINVAL", true},
		{"contains number", "all0wed", false},
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
	_, err := getTracefsPath()
	qt.Assert(t, err, qt.IsNil)
}
