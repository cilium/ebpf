package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
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

func TestMapABIFromProc(t *testing.T) {
	hash, err := NewMap(&MapSpec{
		Type:       Hash,
		KeySize:    4,
		ValueSize:  5,
		MaxEntries: 2,
		Flags:      0x1, // BPF_F_NO_PREALLOC
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hash.Close()

	abi, err := newMapABIFromProc(hash.fd)
	if err != nil {
		t.Fatal("Can't get map ABI:", err)
	}

	if abi.Type != Hash {
		t.Error("Expected Hash, got", abi.Type)
	}

	if abi.KeySize != 4 {
		t.Error("Expected KeySize of 4, got", abi.KeySize)
	}

	if abi.ValueSize != 5 {
		t.Error("Expected ValueSize of 5, got", abi.ValueSize)
	}

	if abi.MaxEntries != 2 {
		t.Error("Expected MaxEntries of 2, got", abi.MaxEntries)
	}

	if abi.Flags != 1 {
		t.Error("Expected Flags to be 1, got", abi.Flags)
	}

	nested, err := NewMap(&MapSpec{
		Type:       ArrayOfMaps,
		KeySize:    4,
		MaxEntries: 2,
		InnerMap: &MapSpec{
			Type:       Array,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 2,
		},
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer nested.Close()

	_, err = newMapABIFromProc(nested.fd)
	if err != nil {
		t.Fatal("Can't get nested map ABI from /proc:", err)
	}
}

func TestProgramABI(t *testing.T) {
	prog := createSocketFilter(t)
	defer prog.Close()

	for name, fn := range map[string]func(*internal.FD) (*ProgramABI, error){
		"generic": newProgramABIFromFd,
		"proc":    newProgramABIFromProc,
	} {
		t.Run(name, func(t *testing.T) {
			abi, err := fn(prog.fd)
			testutils.SkipIfNotSupported(t, err)
			if err != nil {
				t.Fatal("Can't get program ABI:", err)
			}

			if abi.Type != SocketFilter {
				t.Error("Expected Type to be SocketFilter, got", abi.Type)
			}

			if abi.Name != nil {
				if *abi.Name != "test" {
					t.Error("Expected Name to be test, got", *abi.Name)
				}
			}

			if abi.Tag != nil {
				if want := "d7edec644f05498d"; *abi.Tag != want {
					t.Errorf("Expected Tag to be %s, got %s", want, *abi.Tag)
				}
			}
		})
	}
}
