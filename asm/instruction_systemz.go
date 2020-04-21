// +build s390 s390x

package asm

func newBPFRegisters(dst, src Register) bpfRegisters {
	return bpfRegisters((dst << 4) | (src & 0xF))
}

func (r bpfRegisters) Dst() Register {
	return Register(r >> 4)
}

func (r bpfRegisters) Src() Register {
	return Register(r & 0xF)
}
