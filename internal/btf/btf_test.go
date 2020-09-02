package btf

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
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

	spec, err := loadNakedSpec(bytes.NewReader(buf), binary.LittleEndian, nil, nil)
	if err != nil {
		t.Fatal("Can't load BTF:", err)
	}

	var iphdr Struct
	err = spec.FindType("iphdr", &iphdr)
	if err != nil {
		t.Fatalf("unable to find `iphdr` struct: %s", err)
	}
	for _, m := range iphdr.Members {
		if m.Name == "version" {
			// __u8 is a typedef
			td, ok := m.Type.(*Typedef)
			if !ok {
				t.Fatalf("version member of iphdr should be a __u8 typedef: actual: %T", m.Type)
			}
			u8int, ok := td.Type.(*Int)
			if !ok {
				t.Fatalf("__u8 typedef should point to an Int type: actual: %T", td.Type)
			}
			if u8int.Bits != 8 {
				t.Fatalf("incorrect bit size of an __u8 int: expected: 8 actual: %d", u8int.Bits)
			}
			if u8int.Encoding != 0 {
				t.Fatalf("incorrect encoding of an __u8 int: expected: 0 actual: %x", u8int.Encoding)
			}
			if u8int.Offset != 0 {
				t.Fatalf("incorrect int offset of an __u8 int: expected: 0 actual: %d", u8int.Offset)
			}
			return
		}
	}
}

func TestParseCurrentKernelBTF(t *testing.T) {
	spec, err := loadKernelSpec()
	if errors.Is(err, ErrNotFound) {
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
		if err := spec.FindType("totally_bogus_type", &tmp); !errors.Is(err, ErrNotFound) {
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
