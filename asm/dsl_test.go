package asm

import (
	"testing"
)

func TestDSL(t *testing.T) {
	testcases := []struct {
		name string
		have Instruction
		want Instruction
	}{
		{"Call", FnMapLookupElem.Call(), Instruction{OpCode: 0x85, Constant: 1}},
		{"Exit", Return(), Instruction{OpCode: 0x95}},
		{"LoadAbs", LoadAbs(2, Byte), Instruction{OpCode: 0x30, Constant: 2}},
		{"Store", StoreMem(RFP, -4, R0, Word), Instruction{
			OpCode: 0x63,
			Dst:    RFP,
			Src:    R0,
			Offset: -4,
		}},
		{"Add.Imm", Add.Imm(R1, 22), Instruction{OpCode: 0x07, Dst: R1, Constant: 22}},
		{"Add.Reg", Add.Reg(R1, R2), Instruction{OpCode: 0x0f, Dst: R1, Src: R2}},
		{"Add.Imm32", Add.Imm32(R1, 22), Instruction{
			OpCode: 0x04, Dst: R1, Constant: 22,
		}},
		{"JSGT.Imm", JSGT.Imm(R1, 4, "foo"), Instruction{
			OpCode: 0x65, Dst: R1, Constant: 4, Offset: -1,
		}.WithReference("foo")},
		{"JSGT.Imm32", JSGT.Imm32(R1, -2, "foo"), Instruction{
			OpCode: 0x66, Dst: R1, Constant: -2, Offset: -1,
		}.WithReference("foo")},
		{"JSLT.Reg", JSLT.Reg(R1, R2, "foo"), Instruction{
			OpCode: 0xcd, Dst: R1, Src: R2, Offset: -1,
		}.WithReference("foo")},
		{"JSLT.Reg32", JSLT.Reg32(R1, R3, "foo"), Instruction{
			OpCode: 0xce, Dst: R1, Src: R3, Offset: -1,
		}.WithReference("foo")},
	}

	for _, tc := range testcases {
		if !tc.have.equal(tc.want) {
			t.Errorf("%s: have %v, want %v", tc.name, tc.have, tc.want)
		}
	}
}
