package link

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
	qt "github.com/frankban/quicktest"
)

func TestTraceEventTypePMU(t *testing.T) {
	// Requires at least 4.17 (e12f03d7031a "perf/core: Implement the 'perf_kprobe' PMU")
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
	if !errors.Is(err, errInvalidInput) {
		t.Errorf("expected error %s, got: %s", errInvalidInput, err)
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

func TestPerfEventAttach(t *testing.T) {
	baseSpec := &ebpf.ProgramSpec{
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	}

	// Get a random trace event id; for the scope of the test it's not important which one
	tid, err := getTraceEventID("tcp", "tcp_probe")
	if err != nil {
		t.Fatalf("get trace event id: %v", err)
	}
	tfd, err := openTracepointPerfEvent(tid)
	if err != nil {
		t.Fatalf("open tracepoint event: %v", err)
	}

	var tests = []struct {
		name  string
		pe    *perfEvent
		ptype ebpf.ProgramType
		fail  bool
	}{
		{
			name: "attach tracepoint perf event to tracepoint program",
			pe: &perfEvent{
				typ: tracepointEvent,
				fd:  tfd,
			},
			ptype: ebpf.TracePoint,
			fail:  false,
		},
		{
			name: "attach tracepoint perf event to kprobe program",
			pe: &perfEvent{
				typ: tracepointEvent,
				fd:  tfd,
			},
			ptype: ebpf.Kprobe,
			fail:  true,
		},
		{
			name: "missing perf event fd",
			pe: &perfEvent{
				typ: tracepointEvent,
			},
			ptype: ebpf.TracePoint,
			fail:  true,
		},
		{
			name: "ioctl fail",
			pe: &perfEvent{
				typ: kprobeEvent,
				fd:  tfd,
			},
			ptype: ebpf.Kprobe,
			fail:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := baseSpec
			spec.Type = tt.ptype
			prog, err := ebpf.NewProgram(spec)
			if err != nil {
				t.Fatalf("create program from spec: %v", err)
			}
			defer prog.Close()
			defer tt.pe.Close()

			if err := tt.pe.attach(prog); tt.fail != (err != nil) {
				t.Fatalf("perf event attach (fail=%v): %v", tt.fail, err)
			}
		})
	}
}
