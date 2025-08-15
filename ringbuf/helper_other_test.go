//go:build !windows

package ringbuf

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func mustOutputSamplesProg(tb testing.TB, sampleMessages ...sampleMessage) (*ebpf.Program, *ebpf.Map) {
	tb.Helper()

	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.RingBuf,
		MaxEntries: 4096,
	})
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() {
		events.Close()
	})

	var maxSampleSize int
	for _, sampleMessage := range sampleMessages {
		if sampleMessage.size > maxSampleSize {
			maxSampleSize = sampleMessage.size
		}
	}

	insns := asm.Instructions{
		asm.LoadImm(asm.R0, 0x0102030404030201, asm.DWord),
		asm.Mov.Reg(asm.R9, asm.R1),
	}

	bufDwords := (maxSampleSize / 8) + 1
	for i := range bufDwords {
		insns = append(insns,
			asm.StoreMem(asm.RFP, int16(i+1)*-8, asm.R0, asm.DWord),
		)
	}

	for _, sampleMessage := range sampleMessages {
		insns = append(insns,
			asm.LoadMapPtr(asm.R1, events.FD()),
			asm.Mov.Imm(asm.R2, int32(sampleMessage.size)),
			asm.Mov.Imm(asm.R3, int32(0)),
			asm.FnRingbufReserve.Call(),
			asm.JEq.Imm(asm.R0, 0, "exit"),
			asm.Mov.Reg(asm.R5, asm.R0),
		)
		for i := range sampleMessage.size {
			insns = append(insns,
				asm.LoadMem(asm.R4, asm.RFP, int16(i+1)*-1, asm.Byte),
				asm.StoreMem(asm.R5, int16(i), asm.R4, asm.Byte),
			)
		}

		if sampleMessage.discard {
			insns = append(insns,
				asm.Mov.Reg(asm.R1, asm.R5),
				asm.Mov.Imm(asm.R2, sampleMessage.flags),
				asm.FnRingbufDiscard.Call(),
			)
		} else {
			insns = append(insns,
				asm.Mov.Reg(asm.R1, asm.R5),
				asm.Mov.Imm(asm.R2, sampleMessage.flags),
				asm.FnRingbufSubmit.Call(),
			)
		}
	}

	insns = append(insns,
		asm.Mov.Imm(asm.R0, int32(0)).WithSymbol("exit"),
		asm.Return(),
	)

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		License:      "MIT",
		Type:         ebpf.XDP,
		Instructions: insns,
	})
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() {
		prog.Close()
	})

	return prog, events
}
