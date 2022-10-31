package asm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
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

func BenchmarkRead64bitImmediate(b *testing.B) {
	r := &bytes.Reader{}
	for i := 0; i < b.N; i++ {
		r.Reset(test64bitImmProg)

		var ins Instruction
		if _, err := ins.Unmarshal(r, binary.LittleEndian); err != nil {
			b.Fatal(err)
		}
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

func BenchmarkWrite64BitImmediate(b *testing.B) {
	ins := LoadImm(R0, math.MinInt32-1, DWord)

	var buf bytes.Buffer
	for i := 0; i < b.N; i++ {
		buf.Reset()

		if _, err := ins.Marshal(&buf, binary.LittleEndian); err != nil {
			b.Fatal(err)
		}
	}
}

func TestUnmarshalInstructions(t *testing.T) {
	r := bytes.NewReader(test64bitImmProg)

	var insns Instructions
	if err := insns.Unmarshal(r, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}

	// Unmarshaling into the same Instructions multiple times replaces
	// the instruction stream.
	r.Reset(test64bitImmProg)
	if err := insns.Unmarshal(r, binary.LittleEndian); err != nil {
		t.Fatal(err)
	}

	if len(insns) != 1 {
		t.Fatalf("Expected one instruction, got %d", len(insns))
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
	if fd := ins.mapFd(); fd != 1 {
		t.Error("Expected map fd to be 1, got", fd)
	}
	if off := ins.mapOffset(); off != 123 {
		t.Fatal("Expected map offset to be 123 after changin the pointer, got", off)
	}
}

func TestInstructionsRewriteMapPtr(t *testing.T) {
	insns := Instructions{
		LoadMapPtr(R1, 0).WithReference("good"),
		Return(),
	}

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

	if err := insns.RewriteMapPtr("bad", 1); !errors.Is(err, ErrUnreferencedSymbol) {
		t.Error("Rewriting unreferenced map doesn't return appropriate error")
	}
}

func TestInstructionWithMetadata(t *testing.T) {
	ins := LoadImm(R0, 123, DWord).WithSymbol("abc")
	ins2 := LoadImm(R0, 567, DWord).WithMetadata(ins.Metadata)

	if want, got := "abc", ins2.Symbol(); want != got {
		t.Fatalf("unexpected Symbol value on ins2: want: %s, got: %s", want, got)
	}

	if want, got := ins.Metadata, ins2.Metadata; want != got {
		t.Fatal("expected ins and isn2 Metadata to match")
	}
}

// You can use format flags to change the way an eBPF
// program is stringified.
func ExampleInstructions_Format() {

	insns := Instructions{
		FnMapLookupElem.Call().WithSymbol("my_func").WithSource(Comment("bpf_map_lookup_elem()")),
		LoadImm(R0, 42, DWord).WithSource(Comment("abc = 42")),
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
	//	 ; bpf_map_lookup_elem()
	// 	0: Call FnMapLookupElem
	//	 ; abc = 42
	// 	1: LdImmDW dst: r0 imm: 42
	// 	3: Exit
	//
	// Don't indent instructions:
	// my_func:
	//  ; bpf_map_lookup_elem()
	// 0: Call FnMapLookupElem
	//  ; abc = 42
	// 1: LdImmDW dst: r0 imm: 42
	// 3: Exit
	//
	// Indent using spaces:
	// my_func:
	//   ; bpf_map_lookup_elem()
	//  0: Call FnMapLookupElem
	//   ; abc = 42
	//  1: LdImmDW dst: r0 imm: 42
	//  3: Exit
	//
	// Control symbol indentation:
	// 		my_func:
	//	 ; bpf_map_lookup_elem()
	// 	0: Call FnMapLookupElem
	//	 ; abc = 42
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

func TestMetadataCopyOnWrite(t *testing.T) {
	c := qt.New(t)

	// Setting metadata should copy Instruction and modify the metadata pointer
	// of the new object without touching the old Instruction.

	// Reference
	ins := Ja.Label("my_func")
	ins2 := ins.WithReference("my_func2")

	c.Assert(ins.Reference(), qt.Equals, "my_func", qt.Commentf("WithReference updated ins"))
	c.Assert(ins2.Reference(), qt.Equals, "my_func2", qt.Commentf("WithReference didn't update ins2"))

	// Symbol
	ins = Ja.Label("").WithSymbol("my_sym")
	ins2 = ins.WithSymbol("my_sym2")

	c.Assert(ins.Symbol(), qt.Equals, "my_sym", qt.Commentf("WithSymbol updated ins"))
	c.Assert(ins2.Symbol(), qt.Equals, "my_sym2", qt.Commentf("WithSymbol didn't update ins2"))

	// Map
	ins = LoadMapPtr(R1, 0)
	ins2 = ins

	testMap := testFDer(1)
	c.Assert(ins2.AssociateMap(testMap), qt.IsNil, qt.Commentf("failed to associate map with ins2"))

	c.Assert(ins.Map(), qt.IsNil, qt.Commentf("AssociateMap updated ins"))
	c.Assert(ins2.Map(), qt.Equals, testMap, qt.Commentf("AssociateMap didn't update ins2"))
}

type testFDer int

func (t testFDer) FD() int {
	return int(t)
}
