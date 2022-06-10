package btf_test

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func TestNewHandleFromID(t *testing.T) {
	const vmlinux = btf.ID(1)

	// We need to call into the verifier at least once to ensure that
	// vmlinux BTF has been loaded.
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:    ebpf.SocketFilter,
		License: "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	prog.Close()

	h, err := btf.NewHandleFromID(vmlinux)
	if err != nil {
		t.Fatal(err)
	}
	h.Close()
}
