package btf_test

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/btf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestCoreRelocation(t *testing.T) {
	testutils.TestFiles(t, "testdata/*.elf", func(t *testing.T, file string) {
		spec, err := ebpf.LoadCollectionSpec(file)
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal(err)
		}

		for _, prog := range spec.Programs {
			t.Run(prog.Name, func(t *testing.T) {
				relos, err := btf.ProgramRelocations(prog.BTF, btf.ProgramSpec(prog.BTF))
				testutils.SkipIfNotSupported(t, err)
				if err != nil {
					t.Fatal("Can't relocate against itself:", err)
				}

				for i, relo := range relos {
					if relo.Current != relo.New {
						// Since we're relocating against ourselves both values
						// should match.
						t.Errorf("#%d: current %v doesn't match new %d", i, relo.Current, relo.New)
					}
				}
			})
		}
	})
}
