package btf_test

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/testutils"
)

func init() {
	// We need to call into the verifier at least once to ensure that
	// vmlinux BTF has been loaded for TestNewHandleFromID.
	// If there is a call to BPF_BTF_LOAD before BPF_PROG_LOAD then the BTF_LOAD
	// gets ID 1, and vmlinux ID 2.
	// Invoke BPF_PROG_LOAD in init() to guarantee that vmlinux has ID 1.
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.SocketFilter,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		panic(err)
	}
	prog.Close()
}

func TestNewHandleFromID(t *testing.T) {
	const vmlinux = btf.ID(1)

	// See https://github.com/torvalds/linux/commit/5329722057d41aebc31e391907a501feaa42f7d9
	testutils.SkipOnOldKernel(t, "5.11", "vmlinux BTF ID")

	h, err := btf.NewHandleFromID(vmlinux)
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
}
