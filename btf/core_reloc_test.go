package btf_test

import (
	"bytes"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"

	"github.com/go-quicktest/qt"
)

func TestCORERelocationLoad(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/relocs-%s.elf")
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
				KernelTypes: spec.Types,
			})
			testutils.SkipIfNotSupported(t, err)

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

			ret, _, err := prog.Test(internal.EmptyBPFContext)
			testutils.SkipIfNotSupported(t, err)
			if err != nil {
				t.Fatal("Error when running:", err)
			}

			if ret != 0 {
				t.Error("Assertion failed on line", ret)
			}
		})
	}
}

func TestCORERelocationRead(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/relocs_read-%s.elf")
	spec, err := ebpf.LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	targetFile := testutils.NativeFile(t, "testdata/relocs_read_tgt-%s.elf")
	targetSpec, err := btf.LoadSpec(targetFile)
	if err != nil {
		t.Fatal(err)
	}

	for _, progSpec := range spec.Programs {
		t.Run(progSpec.Name, func(t *testing.T) {
			prog, err := ebpf.NewProgramWithOptions(progSpec, ebpf.ProgramOptions{
				KernelTypes: targetSpec,
			})
			testutils.SkipIfNotSupported(t, err)
			if err != nil {
				t.Fatal("Load program:", err)
			}
			defer prog.Close()

			ret, _, err := prog.Test(internal.EmptyBPFContext)
			testutils.SkipIfNotSupported(t, err)
			if err != nil {
				t.Fatal("Error when running:", err)
			}

			if ret != 0 {
				t.Error("Assertion failed on line", ret)
			}
		})
	}
}

func TestLD64IMMReloc(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.4", "vmlinux BTF in sysfs")

	file := testutils.NativeFile(t, "testdata/relocs_enum-%s.elf")
	fh, err := os.Open(file)
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	spec, err := ebpf.LoadCollectionSpecFromReader(fh)
	if err != nil {
		t.Fatal(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()
}

func TestCOREPoisonLineInfo(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.0", "program ext_infos")

	spec, err := ebpf.LoadCollectionSpec(testutils.NativeFile(t, "../testdata/errors-%s.elf"))
	qt.Assert(t, qt.IsNil(err))

	var b btf.Builder
	raw, err := b.Marshal(nil, nil)
	qt.Assert(t, qt.IsNil(err))
	empty, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	qt.Assert(t, qt.IsNil(err))

	for _, test := range []struct {
		name string
	}{
		{"poisoned_single"},
		{"poisoned_double"},
	} {
		progSpec := spec.Programs[test.name]
		qt.Assert(t, qt.IsNotNil(progSpec))

		t.Run(test.name, func(t *testing.T) {
			t.Log(progSpec.Instructions)
			_, err := ebpf.NewProgramWithOptions(progSpec, ebpf.ProgramOptions{
				KernelTypes: empty,
			})
			testutils.SkipIfNotSupported(t, err)

			var ve *ebpf.VerifierError
			qt.Assert(t, qt.ErrorAs(err, &ve))
			found := slices.ContainsFunc(ve.Log, func(line string) bool {
				return strings.HasPrefix(line, "; instruction poisoned by CO-RE")
			})
			qt.Assert(t, qt.IsTrue(found))
			t.Logf("%-5v", ve)
		})
	}
}
