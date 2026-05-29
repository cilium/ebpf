package ebpf

import (
	"bytes"
	"encoding/binary"
	"math"
	"os"
	"testing"
)

func TestStructOpsDatasecOffsetOverflowRepro(t *testing.T) {
	elf, err := os.ReadFile("testdata/struct_ops-el.elf")
	if err != nil {
		t.Fatal(err)
	}

	// In this fixture, symtab entry 4 is testmod_ops and st_value is at 0x308.
	// The .rel.BTF relocation copies that value into the .struct_ops.link DATASEC offset.
	binary.LittleEndian.PutUint64(elf[0x308:], uint64(math.MaxUint32-3))

	_, err = LoadCollectionSpecFromReader(bytes.NewReader(elf))
	if err == nil {
		t.Fatal("expected error")
	}
}
