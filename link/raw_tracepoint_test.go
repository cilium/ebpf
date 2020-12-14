package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestRawTracepoint(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.17", "BPF_RAW_TRACEPOINT API")

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.RawTracepoint,
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
	defer prog.Close()

	link, err := AttachRawTracepoint(RawTracepointOptions{
		Name:    "cgroup_mkdir",
		Program: prog,
	})
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, link, testLinkOptions{
		prog: prog,
	})
}

func TestRawTracepoint_writable(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.2", "BPF_RAW_TRACEPOINT_WRITABLE API")

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.RawTracepointWritable,
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
	defer prog.Close()

	link, err := AttachRawTracepoint(RawTracepointOptions{
		Name:    "cgroup_rmdir",
		Program: prog,
	})
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, link, testLinkOptions{
		prog: prog,
	})
}
