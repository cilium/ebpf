package ebpf

import (
	"fmt"
	"math"
	"testing"
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
	insns := Instructions{
		BPFILdImm64(Reg0, 0).Ref("my_ret"),
		BPFIOp(Exit),
	}

	editor := Edit(&insns)
	if err := editor.RewriteConstant("my_ret", 42); err != nil {
		panic(err)
	}

	fmt.Printf("%0.0s", insns)

	// Output: 0: LdImmDW dst: r0 imm: 42
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

	insns := Instructions{
		BPFILdImm64(Reg1, 0).Ref("my_ret"),
		BPFIDstImm(RShImm, Reg1, 63),
		BPFIDstImm(MovImm, Reg0, 1),
		BPFIDstOffImm(JGTImm, Reg1, 1, 0),
		BPFIDstImm(MovImm, Reg0, 0),
		BPFIOp(Exit),
	}

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
	insns := Instructions{
		// Make sure the call doesn't happen at instruction 0
		// to exercise the relative offset calculation.
		BPFIDstSrc(MovSrc, Reg0, Reg1),
		BPFIDstSrcImm(Call, Reg0, Reg1, -1).Ref("my_func"),
		BPFIOp(Exit),
	}

	editor := Edit(&insns)
	err := editor.Link(Instructions{
		BPFILdImm64(Reg0, 1337).Sym("my_func"),
		BPFIOp(Exit),
	})
	if err != nil {
		t.Fatal(err)
	}

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
