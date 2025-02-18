package unsafe

import (
	"unsafe"

	"github.com/cilium/ebpf"
)

// VariablePointer enables direct access to the variable, bypassing .Get()
// and .Set() API.
//
// The pointer WILL become dangling if the Variable is collected in
// meantime.
//
//go:linkname VariablePointer github.com/cilium/ebpf.unsafeVariablePointer
func VariablePointer(v *ebpf.Variable) (unsafe.Pointer, error)
