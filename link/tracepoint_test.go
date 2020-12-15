package link

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestGetTracepointID(t *testing.T) {
	_, err := getTracepointID("syscalls/sys_enter_open")
	if err != nil {
		t.Fatal("Can't read tracepoint ID:", err)
	}

	_, err = getTracepointID("totally_bogus")
	if !errors.Is(err, internal.ErrNotSupported) {
		t.Fatal("Doesn't return ErrNotSupported")
	}
}

func TestAttachTracepoint(t *testing.T) {
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

	tp, err := AttachTracepoint(TracepointOptions{
		Name:    "syscalls/sys_enter_open",
		Program: prog,
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't attach program:", err)
	}

	if err := tp.Close(); err != nil {
		t.Error("Closing the tracepoint returns an error:", err)
	}
}
