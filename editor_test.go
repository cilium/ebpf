package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/asm"
)

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

func TestEditorRewriteMapOverwrite(t *testing.T) {
	spec, err := LoadCollectionSpec("testdata/rewrite.elf")
	if err != nil {
		t.Fatal(err)
	}
	progSpec := spec.Programs["rewrite_map"]

	// Rewrite once
	array1, err := NewMap(spec.Maps["map_val"])
	if err != nil {
		t.Fatal(err)
	}
	defer array1.Close()

	if err := array1.Put(uint32(0), uint32(42)); err != nil {
		t.Fatal(err)
	}

	if err := Edit(&progSpec.Instructions).RewriteMap("map_val", array1); err != nil {
		t.Fatal(err)
	}

	// Rewrite again
	array2, err := NewMap(spec.Maps["map_val"])
	if err != nil {
		t.Fatal(err)
	}
	defer array2.Close()

	if err := array2.Put(uint32(0), uint32(22)); err != nil {
		t.Fatal(err)
	}

	if err := Edit(&progSpec.Instructions).RewriteMap("map_val", array2); err != nil {
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

	// Last rewrite should win
	if ret != 22 {
		t.Errorf("Expected return value 22, got %d", ret)
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
