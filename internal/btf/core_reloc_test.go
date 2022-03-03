package btf_test

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestCoreRelocationLoad(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/*-el.elf"), func(t *testing.T, file string) {
		fh, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		defer fh.Close()

		spec, err := ebpf.LoadCollectionSpecFromReader(fh)
		if err != nil {
			t.Fatal(err)
		}

		for _, progSpec := range spec.Programs {
			t.Run(progSpec.Name, func(t *testing.T) {
				if _, err := fh.Seek(0, io.SeekStart); err != nil {
					t.Fatal(err)
				}

				prog, err := ebpf.NewProgramWithOptions(progSpec, ebpf.ProgramOptions{
					TargetBTF: fh,
				})

				if strings.HasPrefix(progSpec.Name, "err_") {
					if err == nil {
						prog.Close()
						t.Fatal("Expected an error")
					}
					t.Log("Got expected error:", err)
					return
				}

				if err != nil {
					t.Fatal("Load program:", err)
				}
				defer prog.Close()

				ret, _, err := prog.Test(make([]byte, 14))
				testutils.SkipIfNotSupported(t, err)
				if err != nil {
					t.Fatal("Error when running:", err)
				}

				if ret != 0 {
					t.Error("Assertion failed on line", ret)
				}
			})
		}
	})
}
