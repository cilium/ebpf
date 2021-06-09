package link

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"

	qt "github.com/frankban/quicktest"
)

var (
	tracepointSpec = ebpf.ProgramSpec{
		Type:    ebpf.TracePoint,
		License: "MIT",
		Instructions: asm.Instructions{
			// set exit code to 0
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	}
)

func TestTracepoint(t *testing.T) {

	// Requires at least 4.7 (98b5c2c65c29 "perf, bpf: allow bpf programs attach to tracepoints")
	testutils.SkipOnOldKernel(t, "4.7", "tracepoint support")

	prog, err := ebpf.NewProgram(&tracepointSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	// printk is guaranteed to be present.
	// Kernels before 4.14 don't support attaching to syscall tracepoints.
	tp, err := Tracepoint("printk", "console", prog)
	if err != nil {
		t.Fatal(err)
	}

	if err := tp.Close(); err != nil {
		t.Error("closing tracepoint:", err)
	}
}

func TestTracepointMissing(t *testing.T) {
	prog, err := ebpf.NewProgram(&tracepointSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	_, err = Tracepoint("missing", "foobazbar", prog)
	if !errors.Is(err, os.ErrNotExist) {
		t.Error("Expected os.ErrNotExist, got", err)
	}
}

func TestTracepointErrors(t *testing.T) {
	c := qt.New(t)

	// Invalid Tracepoint incantations.
	_, err := Tracepoint("", "", nil) // empty names
	c.Assert(errors.Is(err, errInvalidInput), qt.IsTrue)

	_, err = Tracepoint("_", "_", nil) // empty prog
	c.Assert(errors.Is(err, errInvalidInput), qt.IsTrue)

	_, err = Tracepoint(".", "+", &ebpf.Program{}) // illegal chars in group/name
	c.Assert(errors.Is(err, errInvalidInput), qt.IsTrue)

	_, err = Tracepoint("foo", "bar", &ebpf.Program{}) // wrong prog type
	c.Assert(errors.Is(err, errInvalidInput), qt.IsTrue)
}

func TestTraceGetEventID(t *testing.T) {
	_, err := getTraceEventID("syscalls", "sys_enter_openat")
	if err != nil {
		t.Fatal("Can't read trace event ID:", err)
	}

	_, err = getTraceEventID("totally", "bogus")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Expected os.ErrNotExist, got", err)
	}
}

func TestTracepointProgramCall(t *testing.T) {
	// Kernels before 4.14 don't support attaching to syscall tracepoints.
	testutils.SkipOnOldKernel(t, "4.14", "syscalls tracepoint support")

	m, p := newUpdaterMapProg(t, ebpf.TracePoint)

	// Open Tracepoint at /sys/kernel/debug/tracing/events/syscalls/sys_enter_getpid
	// and attach it to the ebpf program created above.
	tp, err := Tracepoint("syscalls", "sys_enter_getpid", p)
	if err != nil {
		t.Fatal(err)
	}

	// Trigger ebpf program call.
	unix.Getpid()

	// Assert that the value at index 0 has been updated to 1.
	assertMapValue(t, m, 0, 1)

	// Detach the Tracepoint.
	if err := tp.Close(); err != nil {
		t.Fatal(err)
	}

	// Reset map value to 0 at index 0.
	if err := m.Update(uint32(0), uint32(0), ebpf.UpdateExist); err != nil {
		t.Fatal(err)
	}

	// Retrigger the ebpf program call.
	unix.Getpid()

	// Assert that this time the value has not been updated.
	assertMapValue(t, m, 0, 0)
}
