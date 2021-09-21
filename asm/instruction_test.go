package asm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math"
	"testing"

	qt "github.com/frankban/quicktest"
)

var test64bitImmProg = []byte{
	// r0 = math.MinInt32 - 1
	0x18, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
}

func TestRead64bitImmediate(t *testing.T) {
	var ins Instruction
	n, err := ins.Unmarshal(bytes.NewReader(test64bitImmProg), binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(InstructionSize * 2); n != want {
		t.Errorf("Expected %d bytes to be read, got %d", want, n)
	}

	if c := ins.Constant; c != math.MinInt32-1 {
		t.Errorf("Expected immediate to be %v, got %v", int64(math.MinInt32)-1, c)
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

	err := insns.Marshal(io.Discard, binary.LittleEndian)
	if err != nil {
		t.Error("Can't marshal signed jump:", err)
	}
}

func TestInstructionRewriteMapConstant(t *testing.T) {
	ins := LoadMapValue(R0, 123, 321)

	qt.Assert(t, ins.MapPtr(), qt.Equals, 123)
	qt.Assert(t, ins.mapOffset(), qt.Equals, uint32(321))

	qt.Assert(t, ins.RewriteMapPtr(-1), qt.IsNil)
	qt.Assert(t, ins.MapPtr(), qt.Equals, -1)

	qt.Assert(t, ins.RewriteMapPtr(1), qt.IsNil)
	qt.Assert(t, ins.MapPtr(), qt.Equals, 1)

	// mapOffset should be unchanged after rewriting the pointer.
	qt.Assert(t, ins.mapOffset(), qt.Equals, uint32(321))

	qt.Assert(t, ins.RewriteMapOffset(123), qt.IsNil)
	qt.Assert(t, ins.mapOffset(), qt.Equals, uint32(123))

	// MapPtr should be unchanged.
	qt.Assert(t, ins.MapPtr(), qt.Equals, 1)

	ins = Mov.Imm(R1, 32)
	if err := ins.RewriteMapPtr(1); err == nil {
		t.Error("RewriteMapPtr rewriting bogus instruction")
	}
	if err := ins.RewriteMapOffset(1); err == nil {
		t.Error("RewriteMapOffset rewriting bogus instruction")
	}
}

func TestInstructionLoadMapValue(t *testing.T) {
	ins := LoadMapValue(R0, 1, 123)
	if !ins.IsLoadFromMap() {
		t.Error("isLoadFromMap returns false")
	}
	if fd := ins.MapPtr(); fd != 1 {
		t.Error("Expected map fd to be 1, got", fd)
	}
	if off := ins.mapOffset(); off != 123 {
		t.Fatal("Expected map offset to be 123 after changin the pointer, got", off)
	}
}

func TestInstructionsRewriteMapPtr(t *testing.T) {
	insns := Instructions{
		LoadMapPtr(R1, 0),
		Return(),
	}
	insns[0].Reference = "good"

	if err := insns.RewriteMapPtr("good", 1); err != nil {
		t.Fatal(err)
	}

	if insns[0].Constant != 1 {
		t.Error("Constant should be 1, have", insns[0].Constant)
	}

	if err := insns.RewriteMapPtr("good", 2); err != nil {
		t.Fatal(err)
	}

	if insns[0].Constant != 2 {
		t.Error("Constant should be 2, have", insns[0].Constant)
	}

	if err := insns.RewriteMapPtr("bad", 1); !IsUnreferencedSymbol(err) {
		t.Error("Rewriting unreferenced map doesn't return appropriate error")
	}
}

// You can use format flags to change the way an eBPF
// program is stringified.
func ExampleInstructions_Format() {
	insns := Instructions{
		FnMapLookupElem.Call().Sym("my_func"),
		LoadImm(R0, 42, DWord),
		Return(),
	}

	fmt.Println("Default format:")
	fmt.Printf("%v\n", insns)

	fmt.Println("Don't indent instructions:")
	fmt.Printf("%.0v\n", insns)

	fmt.Println("Indent using spaces:")
	fmt.Printf("% v\n", insns)

	fmt.Println("Control symbol indentation:")
	fmt.Printf("%2v\n", insns)

	// Output: Default format:
	// my_func:
	// 	0: Call FnMapLookupElem
	// 	1: LdImmDW dst: r0 imm: 42
	// 	3: Exit
	//
	// Don't indent instructions:
	// my_func:
	// 0: Call FnMapLookupElem
	// 1: LdImmDW dst: r0 imm: 42
	// 3: Exit
	//
	// Indent using spaces:
	// my_func:
	//  0: Call FnMapLookupElem
	//  1: LdImmDW dst: r0 imm: 42
	//  3: Exit
	//
	// Control symbol indentation:
	// 		my_func:
	// 	0: Call FnMapLookupElem
	// 	1: LdImmDW dst: r0 imm: 42
	// 	3: Exit
}

func TestReadSrcDst(t *testing.T) {
	testSrcDstProg := []byte{
		// on little-endian: r0 = r1
		// on big-endian: be: r1 = r0
		0xbf, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	testcases := []struct {
		bo       binary.ByteOrder
		dst, src Register
	}{
		{binary.BigEndian, R1, R0},
		{binary.LittleEndian, R0, R1},
	}

	for _, tc := range testcases {
		t.Run(tc.bo.String(), func(t *testing.T) {
			var ins Instruction
			_, err := ins.Unmarshal(bytes.NewReader(testSrcDstProg), tc.bo)
			if err != nil {
				t.Fatal(err)
			}
			if ins.Dst != tc.dst {
				t.Errorf("Expected destination to be %v, got %v", tc.dst, ins.Dst)
			}
			if ins.Src != tc.src {
				t.Errorf("Expected source to be %v, got %v", tc.src, ins.Src)
			}
		})
	}
}

func TestInstructionIterator(t *testing.T) {
	insns := Instructions{
		LoadImm(R0, 0, Word),
		LoadImm(R0, 0, DWord),
		Return(),
	}
	offsets := []RawInstructionOffset{0, 1, 3}

	iter := insns.Iterate()
	for i := 0; i < len(insns); i++ {
		if !iter.Next() {
			t.Fatalf("Expected %dth call to Next to return true", i)
		}

		if iter.Ins == nil {
			t.Errorf("Expected iter.Ins to be non-nil")
		}
		if iter.Index != i {
			t.Errorf("Expected iter.Index to be %d, got %d", i, iter.Index)
		}
		if iter.Offset != offsets[i] {
			t.Errorf("Expected iter.Offset to be %d, got %d", offsets[i], iter.Offset)
		}
	}
}
