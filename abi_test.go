package ebpf

import (
	"testing"
)

func TestMapABIEqual(t *testing.T) {
	abi := &MapABI{
		Type:       Array,
		KeySize:    4,
		ValueSize:  2,
		MaxEntries: 3,
		Flags:      1,
	}

	if !abi.Equal(abi) {
		t.Error("Equal returns true when comparing an ABI to itself")
	}

	if abi.Equal(&MapABI{}) {
		t.Error("Equal returns true for different ABIs")
	}
}

func TestProgramABI(t *testing.T) {
	abi := &ProgramABI{Type: SocketFilter}

	if !abi.Equal(abi) {
		t.Error("Equal returns true when comparing an ABI to itself")
	}

	if abi.Equal(&ProgramABI{}) {
		t.Error("Equal returns true for different ABIs")
	}
}
