//go:build !windows

package ringbuf

import (
	"os"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
)

// mustOutputSamplesProg returns a BPF program that outputs the given sample
// messages to a ringbuf.
func mustOutputSamplesProg(tb testing.TB, sampleMessages ...sampleMessage) (*ebpf.Program, *ebpf.Map) {
	tb.Helper()
	return mustOutputSamplesProgN(tb, 1, sampleMessages...)
}

// mustOutputSamplesProgN returns a BPF program that outputs the given sample
// messages to a ringbuf, sizing the map to fit the samples repeated N times.
func mustOutputSamplesProgN(tb testing.TB, repeat int, sampleMessages ...sampleMessage) (*ebpf.Program, *ebpf.Map) {
	tb.Helper()

	var maxSampleSize, totalSize int
	for _, sampleMessage := range sampleMessages {
		if sampleMessage.size > maxSampleSize {
			maxSampleSize = sampleMessage.size
		}
		totalSize += ringbufHeaderSize + internal.Align(sampleMessage.size, 8)
	}
	totalSize *= repeat

	mapSize := os.Getpagesize()
	for mapSize < totalSize {
		mapSize *= 2
	}

	events, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.RingBuf,
		MaxEntries: uint32(mapSize),
	})
	qt.Assert(tb, qt.IsNil(err))
	tb.Cleanup(func() {
		events.Close()
	})

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
