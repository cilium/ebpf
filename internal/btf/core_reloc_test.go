package btf_test

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestCORERelocationLoad(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/relocs-*.elf"), func(t *testing.T, file string) {
		fh, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		defer fh.Close()

		spec, err := ebpf.LoadCollectionSpecFromReader(fh)
		if err != nil {
			t.Fatal(err)
		}

		if spec.ByteOrder != internal.NativeEndian {
			return
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

func TestCORERelocationRead(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/relocs_read-*.elf"), func(t *testing.T, file string) {
		fh, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		defer fh.Close()

		spec, err := ebpf.LoadCollectionSpecFromReader(fh)
		if err != nil {
			t.Fatal(err)
		}

		if spec.ByteOrder != internal.NativeEndian {
			return
		}

		tgt, err := os.Open(fmt.Sprintf("testdata/relocs_read_tgt-%s.elf", internal.ClangEndian))
		if err != nil {
			t.Fatal(err)
		}
		defer tgt.Close()

		testutils.SkipOnOldKernel(t, "4.16", "bpf2bpf calls")

		for _, progSpec := range spec.Programs {
			t.Run(progSpec.Name, func(t *testing.T) {
				if _, err := tgt.Seek(0, io.SeekStart); err != nil {
					t.Fatal(err)
				}

				prog, err := ebpf.NewProgramWithOptions(progSpec, ebpf.ProgramOptions{
					TargetBTF: tgt,
				})
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
