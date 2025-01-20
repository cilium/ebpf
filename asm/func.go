package asm

import (
	"github.com/cilium/ebpf/internal"
)

//go:generate go run golang.org/x/tools/cmd/stringer@latest -output func_string.go -type=BuiltinFunc

// BuiltinFunc is a built-in eBPF function.
type BuiltinFunc uint32

func BuiltinFuncForPlatform(platform string, value uint32) (BuiltinFunc, error) {
	return internal.EncodePlatformConstant[BuiltinFunc](platform, value)
}

func (fn BuiltinFunc) Decode() (string, uint32) {
	return internal.DecodePlatformConstant(fn)
}

// Call emits a function call.
func (fn BuiltinFunc) Call() Instruction {
	return Instruction{
		OpCode:   OpCode(JumpClass).SetJumpOp(Call),
		Constant: int64(fn),
	}
}
