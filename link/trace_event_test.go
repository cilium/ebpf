package link

import (
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
	qt "github.com/frankban/quicktest"
)

func TestTraceEventTypePMU(t *testing.T) {

	testutils.SkipOnOldKernel(t, "4.15", "perf_kprobe PMU")

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
