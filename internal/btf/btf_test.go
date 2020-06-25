package btf

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
	"golang.org/x/xerrors"
)

func TestParseVmlinux(t *testing.T) {
	fh, err := os.Open("testdata/vmlinux-btf.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	rd, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}

	buf, err := ioutil.ReadAll(rd)
	if err != nil {
		t.Fatal(err)
	}

	_, err = loadNakedSpec(bytes.NewReader(buf), binary.LittleEndian, nil, nil)
	if err != nil {
		t.Fatal("Can't load BTF:", err)
	}
}

func TestParseCurrentKernelBTF(t *testing.T) {
	spec, err := loadKernelSpec()
	if xerrors.Is(err, ErrNotFound) {
		t.Skip("BTF is not available:", err)
	}
	if err != nil {
		t.Fatal("Can't load BTF:", err)
	}

	if len(spec.types) == 0 {
		t.Fatal("Empty kernel BTF")
	}
}

func TestLoadSpecFromElf(t *testing.T) {
	testutils.TestFiles(t, "../../testdata/loader-clang-9-*.elf", func(t *testing.T, file string) {
		fh, err := os.Open(file)
		if err != nil {
			t.Fatal(err)
		}
		defer fh.Close()

		spec, err := LoadSpecFromReader(fh)
		if err != nil {
			t.Fatal("Can't load BTF:", err)
		}

		if spec == nil {
			t.Error("No BTF found in ELF")
		}

		if sec, err := spec.Program("xdp", 1); err != nil {
			t.Error("Can't get BTF for the xdp section:", err)
		} else if sec == nil {
			t.Error("Missing BTF for the xdp section")
		}

		if sec, err := spec.Program("socket", 1); err != nil {
			t.Error("Can't get BTF for the socket section:", err)
		} else if sec == nil {
			t.Error("Missing BTF for the socket section")
		}

		var bpfMapDef Struct
		if err := spec.FindType("bpf_map_def", &bpfMapDef); err != nil {
			t.Error("Can't find bpf_map_def:", err)
		}

		var tmp Void
		if err := spec.FindType("totally_bogus_type", &tmp); !xerrors.Is(err, ErrNotFound) {
			t.Error("FindType doesn't return ErrNotFound:", err)
		}

		if spec.byteOrder != internal.NativeEndian {
			return
		}

		t.Run("Handle", func(t *testing.T) {
			btf, err := NewHandle(spec)
			testutils.SkipIfNotSupported(t, err)
			if err != nil {
				t.Fatal("Can't load BTF:", err)
			}
			defer btf.Close()
		})
	})
}

func TestHaveBTF(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBTF)
}

func TestHaveFuncLinkage(t *testing.T) {
	testutils.CheckFeatureTest(t, haveFuncLinkage)
}

func ExampleSpec_FindType() {
	// Acquire a Spec via one of its constructors.
	spec := new(Spec)

	// Declare a variable of the desired type
	var foo Struct

	if err := spec.FindType("foo", &foo); err != nil {
		// There is no struct with name foo, or there
		// are multiple possibilities.
	}

	// We've found struct foo
	fmt.Println(foo.Name)
}
