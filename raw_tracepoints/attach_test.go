package raw_tracepoints_test

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/raw_tracepoints"
)

func TestProgramAttachRawTracepoint(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.17", "BPF_RAW_TRACEPOINT Api")

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type: ebpf.RawTracepoint,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	if err := raw_tracepoints.AttachFD(prog.FD(), "cgroup_mkdir"); err != nil {
		t.Fatal(err)
	}
}
