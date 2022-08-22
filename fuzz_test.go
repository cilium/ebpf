package ebpf

import (
	"bytes"
	"debug/elf"
	"testing"
)

func FuzzLoadCollectionSpec(f *testing.F) {
	f.Add([]byte(elf.ELFMAG))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < len(elf.ELFMAG) {
			t.Skip("input can't be valid ELF")
		}

		spec, err := LoadCollectionSpecFromReader(bytes.NewReader(data))
		if err != nil {
			if spec != nil {
				t.Fatal("spec is not nil")
			}
		} else if spec == nil {
			t.Fatal("spec is nil")
		}
	})
}
