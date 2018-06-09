package ebpf

import (
	"fmt"
	"math"
	"testing"

	"github.com/newtools/ebpf/asm"
)

// ExampleEditor_rewriteConstant shows how to change constants in
// compiled eBPF byte code.
//
// The C should look something like this:
//
//    const unsigned long my_ret;
//    #define VALUE_OF(x) ((typeof(x))(&x))
//    unsigned long func() {
//        return VALUE_OF(my_ret);
//    }
func ExampleEditor_rewriteConstant() {
	// This assembly is roughly equivalent to what clang
	// would emit for the C above.
	insns := asm.Instructions{
		asm.LoadImm(asm.R0, 0, asm.DWord),
		asm.Return(),
	}

	insns[0].Reference = "my_ret"

	editor := Edit(&insns)
	if err := editor.RewriteConstant("my_ret", 42); err != nil {
		panic(err)
	}

	fmt.Printf("%0.0s", insns)

	// Output: 0: LdImmDW dst: r0 imm: 42 <my_ret>
	// 2: Exit
}

func TestEditorRewriteConstant(t *testing.T) {
	spec, err := LoadCollectionSpec("testdata/rewrite.elf")
	if err != nil {
		t.Fatal(err)
	}

	progSpec := spec.Programs["rewrite"]
	editor := Edit(&progSpec.Instructions)

	if err := editor.RewriteConstant("constant", 0x01); err != nil {
		t.Fatal(err)
	}

	if err := editor.RewriteConstant("bogus", 0x01); !IsUnreferencedSymbol(err) {
		t.Error("Rewriting unreferenced symbol doesn't return appropriate error")
	}

	t.Log(progSpec.Instructions)

	prog, err := NewProgram(progSpec)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	ret, _, err := prog.Test(make([]byte, 14))
	if err != nil {
		t.Fatal(err)
	}

	const N = 1 // number of rewrites
	if expected := uint32(1<<N) - 1; ret != expected {
		t.Errorf("Expected return value %d, got %d", expected, ret)
	}
}

func TestEditorIssue59(t *testing.T) {
	max := uint64(math.MaxUint64)

	insns := asm.Instructions{
		asm.LoadImm(asm.R1, 0, asm.DWord),
		asm.RSh.Imm(asm.R1, 63),
		asm.Mov.Imm(asm.R0, 1),
		asm.JGT.Imm(asm.R1, 0, "exit"),
		asm.Mov.Imm(asm.R0, 0),
		asm.Return().Sym("exit"),
	}

	insns[0].Reference = "my_ret"

	editor := Edit(&insns)
	if err := editor.RewriteConstant("my_ret", max); err != nil {
		t.Fatal(err)
	}

	prog, err := NewProgram(&ProgramSpec{
		Type:         XDP,
		License:      "MIT",
		Instructions: insns,
	})
	if err != nil {
		panic(err)
	}

	ret, _, err := prog.Test(make([]byte, 14))
	if err != nil {
		t.Fatal(err)
	}

	if ret != 1 {
		t.Errorf("Expected return of 1, got %d", ret)
	}
}

func TestEditorRewriteMap(t *testing.T) {
	spec, err := LoadCollectionSpec("testdata/rewrite.elf")
	if err != nil {
		t.Fatal(err)
	}

	array, err := NewMap(spec.Maps["map_val"])
	if err != nil {
		t.Fatal(err)
	}
	defer array.Close()

	if err := array.Put(uint32(0), uint32(42)); err != nil {
		t.Fatal(err)
	}

	progSpec := spec.Programs["rewrite_map"]
	editor := Edit(&progSpec.Instructions)

	if err := editor.RewriteMap("map_val", array); err != nil {
		t.Fatal(err)
	}

	if err := editor.RewriteMap("bogus_map", array); !IsUnreferencedSymbol(err) {
		t.Error("Rewriting unreferenced map doesn't return appropriate error")
	}

	prog, err := NewProgram(progSpec)
	if err != nil {
		t.Fatal(err)
	}

	ret, _, err := prog.Test(make([]byte, 14))
	if err != nil {
		t.Fatal(err)
	}

	if ret != 42 {
		t.Errorf("Expected return value 42, got %d", ret)
	}
}

func TestEditorLink(t *testing.T) {
	insns := asm.Instructions{
		// Make sure the call doesn't happen at instruction 0
		// to exercise the relative offset calculation.
		asm.Mov.Reg(asm.R0, asm.R1),
		asm.Call.Label("my_func"),
		asm.Return(),
	}

	editor := Edit(&insns)
	err := editor.Link(asm.Instructions{
		asm.LoadImm(asm.R0, 1337, asm.DWord).Sym("my_func"),
		asm.Return(),
	})
	if err != nil {
		t.Fatal(err)
	}

	t.Log(insns)

	prog, err := NewProgram(&ProgramSpec{
		Type:         XDP,
		Instructions: insns,
		License:      "MIT",
	})
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
