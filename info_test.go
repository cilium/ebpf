package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestMapInfoFromProc(t *testing.T) {
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

	info, err := newMapInfoFromProc(hash.fd)
	if err != nil {
		t.Fatal("Can't get map info:", err)
	}

	if info.Type != Hash {
		t.Error("Expected Hash, got", info.Type)
	}

	if info.KeySize != 4 {
		t.Error("Expected KeySize of 4, got", info.KeySize)
	}

	if info.ValueSize != 5 {
		t.Error("Expected ValueSize of 5, got", info.ValueSize)
	}

	if info.MaxEntries != 2 {
		t.Error("Expected MaxEntries of 2, got", info.MaxEntries)
	}

	if info.Flags != 1 {
		t.Error("Expected Flags to be 1, got", info.Flags)
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

	_, err = newMapInfoFromProc(nested.fd)
	if err != nil {
		t.Fatal("Can't get nested map info from /proc:", err)
	}
}

func TestProgramInfo(t *testing.T) {
	prog := createSocketFilter(t)
	defer prog.Close()

	for name, fn := range map[string]func(*internal.FD) (*ProgramInfo, error){
		"generic": newProgramInfoFromFd,
		"proc":    newProgramInfoFromProc,
	} {
		t.Run(name, func(t *testing.T) {
			info, err := fn(prog.fd)
			testutils.SkipIfNotSupported(t, err)
			if err != nil {
				t.Fatal("Can't get program info:", err)
			}

			if info.Type != SocketFilter {
				t.Error("Expected Type to be SocketFilter, got", info.Type)
			}

			if info.Name != nil {
				if *info.Name != "test" {
					t.Error("Expected Name to be test, got", *info.Name)
				}
			}

			if info.Tag != nil {
				if want := "d7edec644f05498d"; *info.Tag != want {
					t.Errorf("Expected Tag to be %s, got %s", want, *info.Tag)
				}
			}
		})
	}
}
