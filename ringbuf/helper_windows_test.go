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
		Type:       ebpf.WindowsRingBuf,
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
		if sampleMessage.discard {
			tb.Skip("discard is not supported on Windows")
		}

		insns = append(insns,
			asm.LoadMapPtr(asm.R1, events.FD()),
			asm.Mov.Reg(asm.R2, asm.RFP),
			asm.Add.Imm(asm.R2, -int32(8*bufDwords)),
			asm.Mov.Imm(asm.R3, int32(sampleMessage.size)),
			asm.Mov.Imm(asm.R4, sampleMessage.flags),
			asm.WindowsFnRingbufOutput.Call(),
			asm.JNE.Imm(asm.R0, 0, "exit"),
		)
	}

	insns = append(insns,
		asm.Mov.Imm(asm.R0, int32(0)),
		asm.Return().WithSymbol("exit"),
	)

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		License:      "MIT",
		Type:         ebpf.WindowsXDPTest,
		Instructions: insns,
	})
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() {
		prog.Close()
	})

	return prog, events
}
