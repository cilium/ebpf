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

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal/platform"
)

var test64bitImmProg = []byte{
	// r0 = math.MinInt32 - 1
	0x18, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x7f,
	0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
}

func TestRead64bitImmediate(t *testing.T) {
	var ins Instruction
	err := ins.Unmarshal(bytes.NewReader(test64bitImmProg), binary.LittleEndian, platform.Linux)
	if err != nil {
		t.Fatal(err)
	}

	if c := ins.Constant; c != math.MinInt32-1 {
		t.Errorf("Expected immediate to be %v, got %v", int64(math.MinInt32)-1, c)
	}
}

func BenchmarkRead64bitImmediate(b *testing.B) {
	r := &bytes.Reader{}
	for b.Loop() {
		r.Reset(test64bitImmProg)

		var ins Instruction
		if err := ins.Unmarshal(r, binary.LittleEndian, platform.Linux); err != nil {
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
	for b.Loop() {
		buf.Reset()

		if _, err := ins.Marshal(&buf, binary.LittleEndian); err != nil {
			b.Fatal(err)
		}
	}
}

func TestAppendInstructions(t *testing.T) {
	r := bytes.NewReader(test64bitImmProg)

	insns, err := AppendInstructions(nil, r, binary.LittleEndian, platform.Linux)
	qt.Assert(t, qt.IsNil(err))

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

	qt.Assert(t, qt.Equals(ins.MapPtr(), 123))
	qt.Assert(t, qt.Equals(ins.mapOffset(), 321))

	qt.Assert(t, qt.IsNil(ins.RewriteMapPtr(-1)))
	qt.Assert(t, qt.Equals(ins.MapPtr(), -1))

	qt.Assert(t, qt.IsNil(ins.RewriteMapPtr(1)))
	qt.Assert(t, qt.Equals(ins.MapPtr(), 1))

	// mapOffset should be unchanged after rewriting the pointer.
	qt.Assert(t, qt.Equals(ins.mapOffset(), 321))

	qt.Assert(t, qt.IsNil(ins.RewriteMapOffset(123)))
	qt.Assert(t, qt.Equals(ins.mapOffset(), 123))

	// MapPtr should be unchanged.
	qt.Assert(t, qt.Equals(ins.MapPtr(), 1))

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
		t.Fatal("Expected map offset to be 123 after changing the pointer, got", off)
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

func TestReadCallToNegativeOne(t *testing.T) {
	raw := []byte{
		0x85, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
	}
	var ins Instruction
	err := ins.Unmarshal(bytes.NewReader(raw), binary.LittleEndian, platform.Linux)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(ins.Constant, -1))
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
			err := ins.Unmarshal(bytes.NewReader(testSrcDstProg), tc.bo, platform.Linux)
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
	// Setting metadata should copy Instruction and modify the metadata pointer
	// of the new object without touching the old Instruction.

	// Reference
	ins := Ja.Label("my_func")
	ins2 := ins.WithReference("my_func2")

	qt.Assert(t, qt.Equals(ins.Reference(), "my_func"), qt.Commentf("WithReference updated ins"))
	qt.Assert(t, qt.Equals(ins2.Reference(), "my_func2"), qt.Commentf("WithReference didn't update ins2"))

	// Symbol
	ins = Ja.Label("").WithSymbol("my_sym")
	ins2 = ins.WithSymbol("my_sym2")

	qt.Assert(t, qt.Equals(ins.Symbol(), "my_sym"), qt.Commentf("WithSymbol updated ins"))
	qt.Assert(t, qt.Equals(ins2.Symbol(), "my_sym2"), qt.Commentf("WithSymbol didn't update ins2"))

	// Map
	ins = LoadMapPtr(R1, 0)
	ins2 = ins

	testMap := testFDer(1)
	qt.Assert(t, qt.IsNil(ins2.AssociateMap(testMap)), qt.Commentf("failed to associate map with ins2"))

	qt.Assert(t, qt.IsNil(ins.Map()), qt.Commentf("AssociateMap updated ins"))
	qt.Assert(t, qt.Equals[FDer](ins2.Map(), testMap), qt.Commentf("AssociateMap didn't update ins2"))
}

type testFDer int

func (t testFDer) FD() int {
	return int(t)
}

func TestAtomics(t *testing.T) {
	rawInsns := []byte{
		0xc3, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // lock *(u32 *)(r1 + 0x1) += w2
		0xc3, 0x21, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, // lock *(u32 *)(r1 + 0x1) &= w2
		0xc3, 0x21, 0x01, 0x00, 0xa0, 0x00, 0x00, 0x00, // lock *(u32 *)(r1 + 0x1) ^= w2
		0xc3, 0x21, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00, // lock *(u32 *)(r1 + 0x1) |= w2

		0xdb, 0x21, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // lock *(u64 *)(r1 + 0x1) += r2
		0xdb, 0x21, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00, // lock *(u64 *)(r1 + 0x1) &= r2
		0xdb, 0x21, 0x01, 0x00, 0xa0, 0x00, 0x00, 0x00, // lock *(u64 *)(r1 + 0x1) ^= r2
		0xdb, 0x21, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00, // lock *(u64 *)(r1 + 0x1) |= r2

		0xc3, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // w0 = atomic_fetch_add((u32 *)(r1 + 0x0), w0)
		0xc3, 0x01, 0x00, 0x00, 0x51, 0x00, 0x00, 0x00, // w0 = atomic_fetch_and((u32 *)(r1 + 0x0), w0)
		0xc3, 0x01, 0x00, 0x00, 0xa1, 0x00, 0x00, 0x00, // w0 = atomic_fetch_xor((u32 *)(r1 + 0x0), w0)
		0xc3, 0x01, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, // w0 = atomic_fetch_or((u32 *)(r1 + 0x0), w0)

		0xdb, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // r0 = atomic_fetch_add((u64 *)(r1 + 0x0), r0)
		0xdb, 0x01, 0x00, 0x00, 0x51, 0x00, 0x00, 0x00, // r0 = atomic_fetch_and((u64 *)(r1 + 0x0), r0)
		0xdb, 0x01, 0x00, 0x00, 0xa1, 0x00, 0x00, 0x00, // r0 = atomic_fetch_xor((u64 *)(r1 + 0x0), r0)
		0xdb, 0x01, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00, // r0 = atomic_fetch_or((u64 *)(r1 + 0x0), r0)

		0xc3, 0x01, 0x00, 0x00, 0xe1, 0x00, 0x00, 0x00, // w0 = xchg32_32(r1 + 0x0, w0)
		0xdb, 0x01, 0x00, 0x00, 0xe1, 0x00, 0x00, 0x00, // r0 = xchg_64(r1 + 0x0, r0)

		0xc3, 0x11, 0x00, 0x00, 0xf1, 0x00, 0x00, 0x00, // w0 = cmpxchg32_32(r1 + 0x0, w0, w1)
		0xdb, 0x11, 0x00, 0x00, 0xf1, 0x00, 0x00, 0x00, // r0 = cmpxchg_64(r1 + 0x0, r0, r1)
	}

	insns, err := AppendInstructions(nil, bytes.NewReader(rawInsns), binary.LittleEndian, platform.Linux)
	if err != nil {
		t.Fatal(err)
	}

	lines := []string{
		"StXAtomicAddW dst: r1 src: r2 off: 1",
		"StXAtomicAndW dst: r1 src: r2 off: 1",
		"StXAtomicXorW dst: r1 src: r2 off: 1",
		"StXAtomicOrW dst: r1 src: r2 off: 1",
		"StXAtomicAddDW dst: r1 src: r2 off: 1",
		"StXAtomicAndDW dst: r1 src: r2 off: 1",
		"StXAtomicXorDW dst: r1 src: r2 off: 1",
		"StXAtomicOrDW dst: r1 src: r2 off: 1",
		"StXAtomicFetchAddW dst: r1 src: r0 off: 0",
		"StXAtomicFetchAndW dst: r1 src: r0 off: 0",
		"StXAtomicFetchXorW dst: r1 src: r0 off: 0",
		"StXAtomicFetchOrW dst: r1 src: r0 off: 0",
		"StXAtomicFetchAddDW dst: r1 src: r0 off: 0",
		"StXAtomicFetchAndDW dst: r1 src: r0 off: 0",
		"StXAtomicFetchXorDW dst: r1 src: r0 off: 0",
		"StXAtomicFetchOrDW dst: r1 src: r0 off: 0",
		"StXAtomicXchgW dst: r1 src: r0 off: 0",
		"StXAtomicXchgDW dst: r1 src: r0 off: 0",
		"StXAtomicCmpXchgW dst: r1 src: r1 off: 0",
		"StXAtomicCmpXchgDW dst: r1 src: r1 off: 0",
	}

	for i, ins := range insns {
		if want, got := lines[i], fmt.Sprint(ins); want != got {
			t.Errorf("Expected %q, got %q", want, got)
		}
	}

	// Marshal and unmarshal again to make sure the instructions are
	// still valid.
	var buf bytes.Buffer
	err = insns.Marshal(&buf, binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf.Bytes(), rawInsns) {
		t.Error("Expected instructions to be equal after marshalling")
	}
}

func TestISAv4(t *testing.T) {
	rawInsns := []byte{
		0xd7, 0x01, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, // r1 = bswap16 r1
		0xd7, 0x02, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, // r2 = bswap32 r2
		0xd7, 0x03, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, // r3 = bswap64 r3

		0x91, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 = *(s8 *)(r4 + 0x0)
		0x89, 0x52, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // r2 = *(s16 *)(r5 + 0x4)
		0x81, 0x63, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // r3 = *(s32 *)(r6 + 0x8)

		0x91, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 = *(s8 *)(r4 + 0x0)
		0x89, 0x52, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, // r2 = *(s16 *)(r5 + 0x4)

		0xbf, 0x41, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 = (s8)r4
		0xbf, 0x52, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, // r2 = (s16)r5
		0xbf, 0x63, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, // r3 = (s32)r6

		0xbc, 0x31, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, // w1 = (s8)w3
		0xbc, 0x42, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, // w2 = (s16)w4

		0x06, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, // gotol +3

		0x3f, 0x31, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // r1 s/= r3
		0x9f, 0x42, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // r2 s%= r4

		0x3c, 0x31, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // w1 s/= w3
		0x9c, 0x42, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // w2 s%= w4

		0xd3, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // w0 = load_acquire((u8 *)(r1 + 0x0))
		0xcb, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // w0 = load_acquire((u16 *)(r1 + 0x0))
		0xc3, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // w0 = load_acquire((u32 *)(r1 + 0x0))
		0xdb, 0x10, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, // r0 = load_acquire((u64 *)(r1 + 0x0))

		0xd3, 0x21, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, // store_release((u8 *)(r1 + 0x0), w2)
		0xcb, 0x21, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, // store_release((u16 *)(r1 + 0x0), w2)
		0xc3, 0x21, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, // store_release((u32 *)(r1 + 0x0), w2)
		0xdb, 0x21, 0x00, 0x00, 0x10, 0x01, 0x00, 0x00, // store_release((u64 *)(r1 + 0x0), r2)
	}

	insns, err := AppendInstructions(nil, bytes.NewReader(rawInsns), binary.LittleEndian, platform.Linux)
	if err != nil {
		t.Fatal(err)
	}

	lines := []string{
		"BSwap16 dst: r1 ",
		"BSwap32 dst: r2 ",
		"BSwap64 dst: r3 ",
		"LdXMemSXB dst: r1 src: r4 off: 0 imm: 0",
		"LdXMemSXH dst: r2 src: r5 off: 4 imm: 0",
		"LdXMemSXW dst: r3 src: r6 off: 8 imm: 0",
		"LdXMemSXB dst: r1 src: r4 off: 0 imm: 0",
		"LdXMemSXH dst: r2 src: r5 off: 4 imm: 0",
		"MovSX8Reg dst: r1 src: r4",
		"MovSX16Reg dst: r2 src: r5",
		"MovSX32Reg dst: r3 src: r6",
		"MovSX8Reg32 dst: r1 src: r3",
		"MovSX16Reg32 dst: r2 src: r4",
		"Ja32 imm: 3",
		"SDivReg dst: r1 src: r3",
		"SModReg dst: r2 src: r4",
		"SDivReg32 dst: r1 src: r3",
		"SModReg32 dst: r2 src: r4",
		"StXAtomicLdAcqB dst: r0 src: r1 off: 0",
		"StXAtomicLdAcqH dst: r0 src: r1 off: 0",
		"StXAtomicLdAcqW dst: r0 src: r1 off: 0",
		"StXAtomicLdAcqDW dst: r0 src: r1 off: 0",
		"StXAtomicStRelB dst: r1 src: r2 off: 0",
		"StXAtomicStRelH dst: r1 src: r2 off: 0",
		"StXAtomicStRelW dst: r1 src: r2 off: 0",
		"StXAtomicStRelDW dst: r1 src: r2 off: 0",
	}

	for i, ins := range insns {
		if want, got := lines[i], fmt.Sprint(ins); want != got {
			t.Errorf("Expected %q, got %q", want, got)
		}
	}

	// Marshal and unmarshal again to make sure the instructions are
	// still valid.
	var buf bytes.Buffer
	err = insns.Marshal(&buf, binary.LittleEndian)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(buf.Bytes(), rawInsns) {
		t.Error("Expected instructions to be equal after marshalling")
	}
}

func TestLongJumpPatching(t *testing.T) {
	insns := Instructions{
		LongJump("exit"),
		Xor.Reg(R0, R0),
		Xor.Reg(R0, R0),
		Xor.Reg(R0, R0),
		Return().WithSymbol("exit"),
	}

	err := insns.encodeFunctionReferences()
	if err != nil {
		t.Fatal(err)
	}

	if insns[0].Constant != 3 {
		t.Errorf("Expected offset to be 3, got %d", insns[1].Constant)
	}
}
