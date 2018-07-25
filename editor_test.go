package ebpf

import (
	"fmt"
	"testing"
)

func ExampleEditor_RewriteUint64() {
	// The assembly below is roughly equivalent to what LLVM emits
	// for the following C:
	//
	//    const unsigned long my_ret;
	//    unsigned long func() {
	//        return my_ret;
	//    }
	//
	insns := Instructions{
		BPFILdImm64(Reg0, 0).Ref("my_ret"),
		BPFIDstSrc(LdXDW, Reg0, Reg0),
		BPFIOp(Exit),
	}

	editor := Edit(&insns)
	if err := editor.RewriteUint64("my_ret", 42); err != nil {
		panic(err)
	}

	fmt.Printf("%0.0s", insns)

	// Output: 0: LdImmDW dst: r0 imm: 0
	// 2: MovImm dst: r0 imm: 42
	// 3: Exit
}

func TestEditorRewriteGlobalVariables(t *testing.T) {
	spec, err := LoadCollectionSpec("testdata/rewrite.elf")
	if err != nil {
		t.Fatal(err)
	}

	progSpec := spec.Programs["rewrite"]
	editor := Edit(&progSpec.Instructions)

	// Rewrite scalars
	if err := editor.RewriteBool("bool_val", true); err != nil {
		t.Fatal(err)
	}
	if err := editor.RewriteUint8("char_val", 0x02); err != nil {
		t.Fatal(err)
	}
	if err := editor.RewriteUint16("short_val", 0x04); err != nil {
		t.Fatal(err)
	}
	if err := editor.RewriteUint32("int_val", 0x08); err != nil {
		t.Fatal(err)
	}
	if err := editor.RewriteUint64("long_val", 0x10); err != nil {
		t.Fatal(err)
	}

	// Rewrite arrays
	if err := editor.RewriteBoolArray("bool_array", []bool{false, true}); err != nil {
		t.Fatal(err)
	}
	if err := editor.RewriteUint8Array("char_array", []uint8{0, 0x02}); err != nil {
		t.Fatal(err)
	}
	if err := editor.RewriteUint16Array("short_array", []uint16{0, 0x04}); err != nil {
		t.Fatal(err)
	}
	if err := editor.RewriteUint32Array("int_array", []uint32{0, 0x08}); err != nil {
		t.Fatal(err)
	}
	if err := editor.RewriteUint64Array("long_array", []uint64{0, 0x10}); err != nil {
		t.Fatal(err)
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

	const N = 10 // number of rewrites
	if expected := uint32(1<<N) - 1; ret != expected {
		t.Errorf("Expected return value %d, got %d", expected, ret)
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

func TestEditorRejectInvalidRewrites(t *testing.T) {
	spec, err := LoadCollectionSpec("testdata/rewrite.elf")
	if err != nil {
		t.Fatal(err)
	}

	progSpec := spec.Programs["invalid_rewrite"]
	editor := Edit(&progSpec.Instructions)
	if err := editor.RewriteUint64("int_val", 4242); err == nil {
		t.Error("RewriteUint64 did not reject writing to int value")
	}
	if err := editor.RewriteUint64Array("long_array", []uint64{0}); err == nil {
		t.Error("RewriteUint64Array did not check bounds")
	}
	if err := editor.RewriteUint64Array("short_array", []uint64{0, 0}); err == nil {
		t.Error("RewriteUint64Array did not alignment")
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
