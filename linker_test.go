package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestFindReferences(t *testing.T) {
	progs := map[string]*ProgramSpec{
		"entrypoint": {
			Type: SocketFilter,
			Instructions: asm.Instructions{
				// Make sure the call doesn't happen at instruction 0
				// to exercise the relative offset calculation.
				asm.Mov.Reg(asm.R0, asm.R1),
				asm.Call.Label("my_func"),
				asm.Return(),
			},
			License: "MIT",
		},
		"my_other_func": {
			Instructions: asm.Instructions{
				asm.LoadImm(asm.R0, 1337, asm.DWord).Sym("my_other_func"),
				asm.Return(),
			},
		},
		"my_func": {
			Instructions: asm.Instructions{
				asm.Call.Label("my_other_func").Sym("my_func"),
				asm.Return(),
			},
		},
	}

	if err := populateReferences(progs); err != nil {
		t.Fatal(err)
	}

	testutils.SkipOnOldKernel(t, "4.16", "bpf2bpf calls")

	prog, err := NewProgram(progs["entrypoint"])
	if err != nil {
		t.Fatal(err)
	}

	ret, _, err := prog.Test(nil)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 1337 {
		t.Errorf("Expected return code 1337, got %d", ret)
	}
}
