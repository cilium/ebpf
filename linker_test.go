package ebpf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
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

	ret, _, err := prog.Test(make([]byte, 14))
	if err != nil {
		t.Fatal(err)
	}

	if ret != 1337 {
		t.Errorf("Expected return code 1337, got %d", ret)
	}
}

func TestForwardFunctionDeclaration(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/fwd_decl-*.elf"), func(t *testing.T, file string) {
		coll, err := LoadCollectionSpec(file)
		if err != nil {
			t.Fatal(err)
		}

		testutils.SkipOnOldKernel(t, "4.16", "bpf2bpf calls")

		if coll.ByteOrder != internal.NativeEndian {
			return
		}

		spec := coll.Programs["call_fwd"]

		// This program calls an unimplemented forward function declaration.
		_, err = NewProgram(spec)
		if !errors.Is(err, errUnsatisfiedProgram) {
			t.Fatal("Expected an error wrapping errUnsatisfiedProgram, got:", err)
		}

		// Append the implementation of fwd().
		spec.Instructions = append(spec.Instructions,
			asm.Mov.Imm32(asm.R0, 23).Sym("fwd"),
			asm.Return(),
		)

		// The body of the subprog we appended does not come with BTF func_infos,
		// so the verifier will reject it. Load without BTF.
		spec.BTF = nil

		prog, err := NewProgram(spec)
		if err != nil {
			t.Fatal(err)
		}

		ret, _, err := prog.Test(make([]byte, 14))
		if err != nil {
			t.Fatal("Running program:", err)
		}
		if ret != 23 {
			t.Fatalf("Expected 23, got %d", ret)
		}
	})
}
