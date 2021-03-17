package link

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

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

	tp, err := Tracepoint("syscalls", "sys_enter_open")
	if err != nil {
		t.Fatal(err)
	}

	l, err := tp.Attach(prog)
	testutils.SkipIfNotSupported(t, err)
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
