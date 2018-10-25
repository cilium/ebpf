package asm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"math"
	"testing"
)

var test64bitImmProg = []byte{
	// r0 = math.MinInt32 - 1
	0x18, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
}

func TestRead64bitImmediate(t *testing.T) {
	var insns Instructions
	_, err := insns.Unmarshal(bytes.NewReader(test64bitImmProg), binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}

	if len(insns) != 1 {
		t.Fatal("Expected one instruction, got", len(insns))
	}

	if c := insns[0].Constant; c != math.MinInt32-1 {
		t.Errorf("Expected immediate to be %v, got %v", math.MinInt32-1, c)
	}
}

func TestWrite64bitImmediate(t *testing.T) {
	insns := Instructions{
		LoadImm(R0, math.MinInt32-1, DWord),
	}

	var buf bytes.Buffer
	if err := insns.Marshal(&buf, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}

	if prog := buf.Bytes(); !bytes.Equal(prog, test64bitImmProg) {
		t.Errorf("Marshalled program does not match:\n%s", hex.Dump(prog))
	}
}

func TestSignedJump(t *testing.T) {
	insns := Instructions{
		JSGT.Imm(R0, -1, "foo"),
	}

	insns[0].Offset = 1

	err := insns.Marshal(ioutil.Discard, binary.LittleEndian)
	if err != nil {
		t.Error("Can't marshal signed jump:", err)
	}
}

// ExampleInstructions_Format shows the different options available
// to format an instruction stream.
func ExampleInstructions_Format() {
	insns := Instructions{
		MapLookupElement.Call().Sym("my_func"),
		LoadImm(R0, 42, DWord),
		Return(),
	}

	fmt.Println("Default format:")
	fmt.Printf("%v", insns)

	fmt.Println("Don't indent instructions:")
	fmt.Printf("%.0v", insns)

	fmt.Println("Indent using spaces:")
	fmt.Printf("% v", insns)

	fmt.Println("Control symbol indentation:")
	fmt.Printf("%2v", insns)

	// Output: Default format:
	// my_func:
	// 	0: Call MapLookupElement
	// 	1: LdImmDW dst: r0 imm: 42
	// 	3: Exit
	// Don't indent instructions:
	// my_func:
	// 0: Call MapLookupElement
	// 1: LdImmDW dst: r0 imm: 42
	// 3: Exit
	// Indent using spaces:
	// my_func:
	//  0: Call MapLookupElement
	//  1: LdImmDW dst: r0 imm: 42
	//  3: Exit
	// Control symbol indentation:
	// 		my_func:
	// 	0: Call MapLookupElement
	// 	1: LdImmDW dst: r0 imm: 42
	// 	3: Exit
}
