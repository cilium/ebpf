package features

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
)

// HaveLargeInstructions probes the running kernel if more than 4096 instructions
// per program are supported.
//
// Upstream commit c04c0d2b968ac45d6ef020316808ef6c82325a82.
//
// See the package documentation for the meaning of the error return value.
var HaveLargeInstructions = internal.NewFeatureTest(">4096 instructions", "5.2", func() error {
	const maxInsns = 4096

	insns := make(asm.Instructions, maxInsns, maxInsns+1)
	for i := range insns {
		insns[i] = asm.Mov.Imm(asm.R0, 1)
	}
	insns = append(insns, asm.Return())

	return probeProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SocketFilter,
		Instructions: insns,
	})
})

// HaveBoundedLoops probes the running kernel if bounded loops are supported.
//
// Upstream commit 2589726d12a1b12eaaa93c7f1ea64287e383c7a5.
//
// See the package documentation for the meaning of the error return value.
var HaveBoundedLoops = internal.NewFeatureTest("bounded loops", "5.3", func() error {
	return probeProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 10),
			asm.Sub.Imm(asm.R0, 1).WithSymbol("loop"),
			asm.JNE.Imm(asm.R0, 0, "loop"),
			asm.Return(),
		},
	})
})

// HaveV2ISA probes the running kernel if instructions of the v2 ISA are supported.
//
// Upstream commit 92b31a9af73b3a3fc801899335d6c47966351830.
//
// See the package documentation for the meaning of the error return value.
var HaveV2ISA = internal.NewFeatureTest("v2 ISA", "4.14", func() error {
	return probeProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.JLT.Imm(asm.R0, 0, "exit"),
			asm.Mov.Imm(asm.R0, 1),
			asm.Return().WithSymbol("exit"),
		},
	})
})

// HaveV3ISA probes the running kernel if instructions of the v3 ISA are supported.
//
// Upstream commit 092ed0968bb648cd18e8a0430cd0a8a71727315c.
//
// See the package documentation for the meaning of the error return value.
var HaveV3ISA = internal.NewFeatureTest("v3 ISA", "5.1", func() error {
	return probeProgram(&ebpf.ProgramSpec{
		Type: ebpf.SocketFilter,
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.JLT.Imm32(asm.R0, 0, "exit"),
			asm.Mov.Imm(asm.R0, 1),
			asm.Return().WithSymbol("exit"),
		},
	})
})
