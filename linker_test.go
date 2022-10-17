package ebpf

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"

	qt "github.com/frankban/quicktest"
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
				asm.LoadImm(asm.R0, 1337, asm.DWord).WithSymbol("my_other_func"),
				asm.Return(),
			},
		},
		"my_func": {
			Instructions: asm.Instructions{
				asm.Call.Label("my_other_func").WithSymbol("my_func"),
				asm.Return(),
			},
		},
	}

	flattenPrograms(progs, []string{"entrypoint"})

	prog, err := NewProgram(progs["entrypoint"])
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	ret, _, err := prog.Test(internal.EmptyBPFContext)
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

		if coll.ByteOrder != internal.NativeEndian {
			return
		}

		spec := coll.Programs["call_fwd"]

		// This program calls an unimplemented forward function declaration.
		_, err = NewProgram(spec)
		if !errors.Is(err, asm.ErrUnsatisfiedProgramReference) {
			t.Fatal("Expected an error wrapping ErrUnsatisfiedProgramReference, got:", err)
		}

		// Append the implementation of fwd().
		spec.Instructions = append(spec.Instructions,
			asm.Mov.Imm32(asm.R0, 23).WithSymbol("fwd"),
			asm.Return(),
		)

		// The body of the subprog we appended does not come with BTF func_infos,
		// so the verifier will reject it. Load without BTF.
		for i, ins := range spec.Instructions {
			if btf.FuncMetadata(&ins) != nil || ins.Source() != nil {
				sym := ins.Symbol()
				ref := ins.Reference()
				ins.Metadata = asm.Metadata{}
				spec.Instructions[i] = ins.WithSymbol(sym).WithReference(ref)
			}
		}

		prog, err := NewProgram(spec)
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatalf("%+v", err)
		}
		defer prog.Close()

		ret, _, err := prog.Test(internal.EmptyBPFContext)
		if err != nil {
			t.Fatal("Running program:", err)
		}
		if ret != 23 {
			t.Fatalf("Expected 23, got %d", ret)
		}
	})
}

func TestSplitSymbols(t *testing.T) {
	c := qt.New(t)

	// Splitting an empty insns results in an error.
	_, err := splitSymbols(asm.Instructions{})
	c.Assert(err, qt.IsNotNil, qt.Commentf("empty insns"))

	// Splitting non-empty insns without a leading Symbol is an error.
	_, err = splitSymbols(asm.Instructions{
		asm.Return(),
	})
	c.Assert(err, qt.IsNotNil, qt.Commentf("insns without leading Symbol"))

	// Non-empty insns with a single Instruction that is a Symbol.
	insns := asm.Instructions{
		asm.Return().WithSymbol("sym"),
	}
	m, err := splitSymbols(insns)
	c.Assert(err, qt.IsNil, qt.Commentf("insns with a single Symbol"))

	c.Assert(len(m), qt.Equals, 1)
	c.Assert(len(m["sym"]), qt.Equals, 1)

	// Insns containing duplicate Symbols.
	_, err = splitSymbols(asm.Instructions{
		asm.Return().WithSymbol("sym"),
		asm.Return().WithSymbol("sym"),
	})
	c.Assert(err, qt.IsNotNil, qt.Commentf("insns containing duplicate Symbols"))

	// Insns with multiple Symbols and subprogs of various lengths.
	m, err = splitSymbols(asm.Instructions{
		asm.Return().WithSymbol("sym1"),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("sym2"),
		asm.Return(),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("sym3"),
		asm.Mov.Imm(asm.R0, 1),
		asm.Return(),

		asm.Mov.Imm(asm.R0, 0).WithSymbol("sym4"),
		asm.Mov.Imm(asm.R0, 1),
		asm.Mov.Imm(asm.R0, 2),
		asm.Return(),
	})
	c.Assert(err, qt.IsNil, qt.Commentf("insns with multiple Symbols"))

	c.Assert(len(m), qt.Equals, 4)
	c.Assert(len(m["sym1"]), qt.Equals, 1)
	c.Assert(len(m["sym2"]), qt.Equals, 2)
	c.Assert(len(m["sym3"]), qt.Equals, 3)
	c.Assert(len(m["sym4"]), qt.Equals, 4)
}
