package ebpf

import (
	"testing"

	"github.com/newtools/ebpf/asm"
)

func TestCollectionSpecNotModified(t *testing.T) {
	cs := CollectionSpec{
		Maps: map[string]*MapSpec{
			"my-map": {
				Type:       Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
			},
		},
		Programs: map[string]*ProgramSpec{
			"test": {
				Type: SocketFilter,
				Instructions: asm.Instructions{
					asm.LoadMapPtr(asm.R1, 0),
					asm.LoadImm(asm.R0, 0, asm.DWord),
					asm.Return(),
				},
				License: "MIT",
			},
		},
	}

	cs.Programs["test"].Instructions[0].Reference = "my-map"

	coll, err := NewCollection(&cs)
	if err != nil {
		t.Fatal(err)
	}
	coll.Close()

	if cs.Programs["test"].Instructions[0].Constant != 0 {
		t.Error("Creating a collection modifies input spec")
	}
}
