// +build !s390,!s390x

package asm

func newBPFRegisters(dst, src Register) bpfRegisters {
	return bpfRegisters((src << 4) | (dst & 0xF))
}

func (r bpfRegisters) Dst() Register {
	return Register(r & 0xF)
}

func (r bpfRegisters) Src() Register {
	return Register(r >> 4)
}
