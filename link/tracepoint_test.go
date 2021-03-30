package link

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestTracepoint(t *testing.T) {
	tp, err := Tracepoint("syscalls", "sys_enter_open")
	if err != nil {
		t.Error("opening tracepoint:", err)
	}
	if tp.Close() != nil {
		t.Error("closing tracepoint:", err)
	}

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

func TestTracepointAttach(t *testing.T) {

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
	tp, err := Tracepoint("printk", "console")
	if err != nil {
		t.Fatal(err)
	}

	l, err := tp.Attach(prog)
	if err != nil {
		t.Fatal("attaching program:", err)
	}

	if err := l.Close(); err != nil {
		t.Fatal("closing perf event:", err)
	}

	if err := tp.Close(); err != nil {
		t.Error("closing tracepoint:", err)
	}
}
