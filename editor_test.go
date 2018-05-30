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

	// Output: 0: LdImmDW dst: r0 imm: 42
	// 2: MovSrc dst: r0 src: r0
	// 3: Exit
}

func TestEditorRewriteGlobalVariables(t *testing.T) {
	spec, err := NewCollectionSpecFromFile("testdata/rewrite.elf")
	if err != nil {
		t.Fatal(err)
	}

	progSpec := spec.Programs["xdp_prog"]
	editor := Edit(&progSpec.Instructions)
	if err := editor.RewriteUint64("long_val", 4242); err != nil {
		t.Fatal(err)
	}
	if err := editor.RewriteUint32("int_val", 1234); err != nil {
		t.Fatal(err)
	}
	if err := editor.RewriteUint16("short_val", 2323); err != nil {
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

	if ret != 1234 {
		t.Errorf("Expected return value 1234, got %d", ret)
	}
}

func TestEditorRejectInvalidRewrites(t *testing.T) {
	spec, err := NewCollectionSpecFromFile("testdata/rewrite.elf")
	if err != nil {
		t.Fatal(err)
	}

	progSpec := spec.Programs["invalid_xdp_prog"]
	editor := Edit(&progSpec.Instructions)
	if err := editor.RewriteUint64("int_val", 4242); err == nil {
		t.Error("RewriteUint64 did not reject writing to int value")
	}
	if err := editor.RewriteUint64("long_array", 4242); err == nil {
		t.Error("RewriteUint64 did not reject rewriting an array")
	}
}

func TestEditorLink(t *testing.T) {
	insns := Instructions{
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
