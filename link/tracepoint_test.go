package link

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"

	qt "github.com/frankban/quicktest"
)

func TestTracepoint(t *testing.T) {

	// Requires at least 4.7 (98b5c2c65c29 "perf, bpf: allow bpf programs attach to tracepoints")
	testutils.SkipOnOldKernel(t, "4.7", "tracepoint support")

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.TracePoint,
		License: "MIT",
		Instructions: asm.Instructions{
			// set exit code to 0
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
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
	_, err := getTraceEventID("syscalls", "sys_enter_open")
	if err != nil {
		t.Fatal("Can't read trace event ID:", err)
	}

	_, err = getTraceEventID("totally", "bogus")
	if !errors.Is(err, internal.ErrNotSupported) {
		t.Fatal("Doesn't return ErrNotSupported")
	}
}
