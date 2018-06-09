package asm

import (
	"testing"
)

// These are the old names, retained here to check what
// changes have been made.
func TestOpCodeString(t *testing.T) {
	t.Skip()

	testcases := map[string]OpCode{
		// AddImm  add dst, imm   |  dst += imm
		"AddImm": 0x07,
		// AddSrc  add dst, src   |  dst += src
		"AddSrc": 0x0f,
		// SubImm  sub dst, imm   |  dst -= imm
		"SubImm": 0x17,
		// SubSrc  sub dst, src   |  dst -= src
		"SubSrc": 0x1f,
		// MulImm  mul dst, imm   |  dst *= imm
		"MulImm": 0x27,
		// MulSrc  mul dst, src   |  dst *= src
		"MulSrc": 0x2f,
		// DivImm  div dst, imm   |  dst /= imm
		"DivImm": 0x37,
		// DivSrc  div dst, src   |  dst /= src
		"DivSrc": 0x3f,
		// OrImm   or dst, imm    |  dst  |= imm
		"OrImm": 0x47,
		// OrSrc   or dst, src    |  dst  |= src
		"OrSrc": 0x4f,
		// AndImm  and dst, imm   |  dst &= imm
		"AndImm": 0x57,
		// AndSrc  and dst, src   |  dst &= src
		"AndSrc": 0x5f,
		// LShImm  lsh dst, imm   |  dst <<= imm
		"LShImm": 0x67,
		// LShSrc  lsh dst, src   |  dst <<= src
		"LShSrc": 0x6f,
		// RShImm  rsh dst, imm   |  dst >>= imm (logical)
		"RShImm": 0x77,
		// RShSrc  rsh dst, src   |  dst >>= src (logical)
		"RShSrc": 0x7f,
		// Neg     neg dst        |  dst = -dst
		"Neg": 0x87,
		// ModImm  mod dst, imm   |  dst %= imm
		"ModImm": 0x97,
		// ModSrc  mod dst, src   |  dst %= src
		"ModSrc": 0x9f,
		// XorImm  xor dst, imm   |  dst ^= imm
		"XorImm": 0xa7,
		// XorSrc  xor dst, src   |  dst ^= src
		"XorSrc": 0xaf,
		// MovImm  mov dst, imm   |  dst = imm
		"MovImm": 0xb7,
		// MovSrc  mov dst, src   |  dst = src
		"MovSrc": 0xbf,
		// ArShImm arsh dst, imm  |  dst >>= imm (arithmetic)
		"ArShImm": 0xc7,
		// ArShSrc arsh dst, src  |  dst >>= src (arithmetic)
		"ArShSrc": 0xcf,
		// Add32Imm add32 dst, imm  |  dst += imm
		"Add32Imm": 0x04,
		// Add32Src add32 dst, src  |  dst += src
		"Add32Src": 0x0c,
		// Sub32Imm sub32 dst, imm  |  dst -= imm
		"Sub32Imm": 0x14,
		// Sub32Src sub32 dst, src  |  dst -= src
		"Sub32Src": 0x1c,
		// Mul32Imm mul32 dst, imm  |  dst *= imm
		"Mul32Imm": 0x24,
		// Mul32Src mul32 dst, src  |  dst *= src
		"Mul32Src": 0x2c,
		// Div32Imm div32 dst, imm  |  dst /= imm
		"Div32Imm": 0x34,
		// Div32Src div32 dst, src  |  dst /= src
		"Div32Src": 0x3c,
		// Or32Imm  or32 dst, imm   |  dst |= imm
		"Or32Imm": 0x44,
		// Or32Src  or32 dst, src   |  dst |= src
		"Or32Src": 0x4c,
		// And32Imm and32 dst, imm  |  dst &= imm
		"And32Imm": 0x54,
		// And32Src and32 dst, src  |  dst &= src
		"And32Src": 0x5c,
		// LSh32Imm lsh32 dst, imm  |  dst <<= imm
		"LSh32Imm": 0x64,
		// LSh32Src lsh32 dst, src  |  dst <<= src
		"LSh32Src": 0x6c,
		// RSh32Imm rsh32 dst, imm  |  dst >>= imm (logical)
		"RSh32Imm": 0x74,
		// RSh32Src rsh32 dst, src  |  dst >>= src (logical)
		"RSh32Src": 0x7c,
		// Neg32    neg32 dst       |  dst = -dst
		"Neg32": 0x84,
		// Mod32Imm mod32 dst, imm  |  dst %= imm
		"Mod32Imm": 0x94,
		// Mod32Src mod32 dst, src  |  dst %= src
		"Mod32Src": 0x9c,
		// Xor32Imm xor32 dst, imm  |  dst ^= imm
		"Xor32Imm": 0xa4,
		// Xor32Src xor32 dst, src  |  dst ^= src
		"Xor32Src": 0xac,
		// Mov32Imm mov32 dst, imm  |  dst eBPF only
		"Mov32Imm": 0xb4,
		// Mov32Src mov32 dst, src  |  dst eBPF only
		"Mov32Src": 0xbc,
		// LE16 le16 dst, imm == 16  |  dst = htole16(dst)
		"LE16": 0xd4,
		// LE32 le32 dst, imm == 32  |  dst = htole32(dst)
		"LE32": 0xd4,
		// LE64 le64 dst, imm == 64  |  dst = htole64(dst)
		"LE64": 0xd4,
		// BE16 be16 dst, imm == 16  |  dst = htobe16(dst)
		"BE16": 0xdc,
		// BE32 be32 dst, imm == 32  |  dst = htobe32(dst)
		"BE32": 0xdc,
		// BE64 be64 dst, imm == 64  |  dst = htobe64(dst)
		"BE64": 0xdc,
		// LdDW      lddw (src), dst, imm   |  dst = imm
		"LdDW": 0x18,
		// XAddStSrc xadd dst, src          |  *dst += src
		"XAddStSrc": 0xdb,
		// LdAbsB    ldabsb imm             |  r0 = (uint8_t *) (mem + imm)
		"LdAbsB": 0x30,
		// LdXW      ldxw dst, [src+off]    |  dst = *(uint32_t *) (src + off)
		"LdXW": 0x61,
		// LdXH      ldxh dst, [src+off]    |  dst = *(uint16_t *) (src + off)
		"LdXH": 0x69,
		// LdXB      ldxb dst, [src+off]    |  dst = *(uint8_t *) (src + off)
		"LdXB": 0x71,
		// LdXDW     ldxdw dst, [src+off]   |  dst = *(uint64_t *) (src + off)
		"LdXDW": 0x79,
		// StB       stb [dst+off], imm     |  *(uint8_t *) (dst + off) = imm
		"StB": 0x72,
		// StH       sth [dst+off], imm     |  *(uint16_t *) (dst + off) = imm
		"StH": 0x6a,
		// StW       stw [dst+off], imm     |  *(uint32_t *) (dst + off) = imm
		"StW": 0x62,
		// StDW      stdw [dst+off], imm    |  *(uint64_t *) (dst + off) = imm
		"StDW": 0x7a,
		// StXB      stxb [dst+off], src    |  *(uint8_t *) (dst + off) = src
		"StXB": 0x73,
		// StXH      stxh [dst+off], src    |  *(uint16_t *) (dst + off) = src
		"StXH": 0x6b,
		// StXW      stxw [dst+off], src    |  *(uint32_t *) (dst + off) = src
		"StXW": 0x63,
		// StXDW     stxdw [dst+off], src   |  *(uint64_t *) (dst + off) = src
		"StXDW": 0x7b,
		// LdAbsH  ldabsh imm             |  r0 = (uint16_t *) (imm)
		// Abs and Ind reference memory directly. This is always the context,
		// of whatever the eBPF program is. For example in a sock filter program
		// the memory context is the sk_buff struct.
		"LdAbsH": 0x28,
		// LdAbsW  ldabsw imm             |  r0 = (uint32_t *) (imm)
		"LdAbsW": 0x20,
		// LdAbsDW ldabsdw imm            |  r0 = (uint64_t *) (imm)
		"LdAbsDW": 0x38,
		// LdIndB  ldindb src, dst, imm   |  dst = (uint64_t *) (src + imm)
		"LdIndB": 0x50,
		// LdIndH  ldindh src, dst, imm   |  dst = (uint16_t *) (src + imm)
		"LdIndH": 0x48,
		// LdIndW  ldindw src, dst, imm   |  dst = (uint32_t *) (src + imm)
		"LdIndW": 0x40,
		// LdIndDW ldinddw src, dst, imm  |  dst = (uint64_t *) (src + imm)
		"LdIndDW": 0x58,
		// Ja      ja +off             |  PC += off
		"Ja": 0x05,
		// JEqImm  jeq dst, imm, +off  |  PC += off if dst == imm
		"JEqImm": 0x15,
		// JEqSrc  jeq dst, src, +off  |  PC += off if dst == src
		"JEqSrc": 0x1d,
		// JGTImm  jgt dst, imm, +off  |  PC += off if dst > imm
		"JGTImm": 0x25,
		// JGTSrc  jgt dst, src, +off  |  PC += off if dst > src
		"JGTSrc": 0x2d,
		// JGEImm  jge dst, imm, +off  |  PC += off if dst >= imm
		"JGEImm": 0x35,
		// JGESrc  jge dst, src, +off  |  PC += off if dst >= src
		"JGESrc": 0x3d,
		// JSETImm jset dst, imm, +off |  PC += off if dst & imm
		"JSETImm": 0x45,
		// JSETSrc jset dst, src, +off |  PC += off if dst & src
		"JSETSrc": 0x4d,
		// JNEImm  jne dst, imm, +off  |  PC += off if dst != imm
		"JNEImm": 0x55,
		// JNESrc  jne dst, src, +off  |  PC += off if dst != src
		"JNESrc": 0x5d,
		// JSGTImm jsgt dst, imm, +off |  PC += off if dst > imm (signed)
		"JSGTImm": 0x65,
		// JSGTSrc jsgt dst, src, +off |  PC += off if dst > src (signed)
		"JSGTSrc": 0x6d,
		// JSGEImm jsge dst, imm, +off |  PC += off if dst >= imm (signed)
		"JSGEImm": 0x75,
		// JSGESrc jsge dst, src, +off |  PC += off if dst >= src (signed)
		"JSGESrc": 0x7d,
		// Call    call imm            |  Function call
		"Call": 0x85,
		// Exit    exit                |  return r0
		"Exit": 0x95,
	}

	for want, op := range testcases {
		if have := op.String(); want != have {
			t.Errorf("Expected %s, got %s", want, have)
		}
	}
}
