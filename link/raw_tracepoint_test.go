package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestRawTracepoint(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.17", "BPF_RAW_TRACEPOINT API")

	prog := mustRawTracepointProgram(t, ebpf.RawTracepoint)
	defer prog.Close()

	link, err := AttachRawTracepoint(RawTracepointOptions{
		Name:    "cgroup_mkdir",
		Program: prog,
	})
	if err != nil {
		t.Fatal("Can't create link:", err)
	}

	prog2 := mustRawTracepointProgram(t, ebpf.RawTracepoint)
	defer prog2.Close()

	testLink(t, link, testLinkOptions{
		prog: prog2,
	})
}

func TestRawTracepoint_writable(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.2", "BPF_RAW_TRACEPOINT_WRITABLE API")

	prog := mustRawTracepointProgram(t, ebpf.RawTracepointWritable)
	defer prog.Close()

	link, err := AttachRawTracepoint(RawTracepointOptions{
		Name:    "cgroup_rmdir",
		Program: prog,
	})
	if err != nil {
		t.Fatal("Can't create link:", err)
	}

	prog2 := mustRawTracepointProgram(t, ebpf.RawTracepointWritable)
	defer prog2.Close()

	testLink(t, link, testLinkOptions{
		prog: prog2,
	})
}

func mustRawTracepointProgram(t *testing.T, typ ebpf.ProgramType) *ebpf.Program {
	t.Helper()

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       typ,
		AttachType: ebpf.AttachNone,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "GPL",
	})
	if err != nil {
		t.Fatal(err)
	}
	return prog
}
