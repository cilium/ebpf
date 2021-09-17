package btf

import (
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestFindType(t *testing.T) {
	fh, err := os.Open("testdata/vmlinux-btf.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	rd, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	spec, err := loadRawSpec(rd, binary.LittleEndian, nil, nil)
	if err != nil {
		t.Fatal("Can't load BTF:", err)
	}

	// spec.FindType MUST fail if typ is not a non-nil **T, where T satisfies btf.Type.
	i := 0
	p := &i
	for _, typ := range []interface{}{
		nil,
		Struct{},
		&Struct{},
		[]Struct{},
		&[]Struct{},
		map[int]Struct{},
		&map[int]Struct{},
		p,
		&p,
	} {
		if err := spec.FindType("iphdr", typ); err == nil {
			t.Fatalf("FindType does not fail with type %T", typ)
		}
	}

	// spec.FindType MUST return the same address for multiple calls with the same type name.
	var iphdr1, iphdr2 *Struct
	if err := spec.FindType("iphdr", &iphdr1); err != nil {
		t.Fatal(err)
	}
	if err := spec.FindType("iphdr", &iphdr2); err != nil {
		t.Fatal(err)
	}

	if iphdr1 != iphdr2 {
		t.Fatal("multiple FindType calls for `iphdr` name do not return the same addresses")
	}
}

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

	spec, err := loadRawSpec(rd, binary.LittleEndian, nil, nil)
	if err != nil {
		t.Fatal("Can't load BTF:", err)
	}

	var iphdr *Struct
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
			if u8int.OffsetBits != 0 {
				t.Fatalf("incorrect int offset of an __u8 int: expected: 0 actual: %d", u8int.OffsetBits)
			}
			break
		}
	}
}

func TestParseCurrentKernelBTF(t *testing.T) {
	spec, err := loadKernelSpec()
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't load BTF:", err)
	}

	if len(spec.namedTypes) == 0 {
		t.Fatal("Empty kernel BTF")
	}
}

func TestLoadSpecFromElf(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "../../testdata/loader-e*.elf"), func(t *testing.T, file string) {
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

		var bpfMapDef *Struct
		if err := spec.FindType("bpf_map_def", &bpfMapDef); err != nil {
			t.Error("Can't find bpf_map_def:", err)
		}

		var tmp *Void
		if err := spec.FindType("totally_bogus_type", &tmp); !errors.Is(err, ErrNotFound) {
			t.Error("FindType doesn't return ErrNotFound:", err)
		}

		var fn *Func
		if err := spec.FindType("global_fn", &fn); err != nil {
			t.Error("Can't find global_fn():", err)
		} else {
			if fn.Linkage != GlobalFunc {
				t.Error("Expected global linkage:", fn)
			}
		}

		var v *Var
		if err := spec.FindType("key3", &v); err != nil {
			t.Error("Cant find key3:", err)
		} else {
			if v.Linkage != GlobalVar {
				t.Error("Expected global linkage:", v)
			}
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

func TestLoadKernelSpec(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		t.Skip("/sys/kernel/btf/vmlinux not present")
	}

	_, err := LoadKernelSpec()
	if err != nil {
		t.Fatal("Can't load kernel spec:", err)
	}
}

func TestSpecCopy(t *testing.T) {
	fh, err := os.Open("../../testdata/loader-el.elf")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	spec, err := LoadSpecFromReader(fh)
	if err != nil {
		t.Fatal("Can't load BTF:", err)
	}

	if len(spec.types) < 1 {
		t.Fatal("Not enough types")
	}

	cpy := spec.Copy()
	for i := range cpy.types {
		if _, ok := cpy.types[i].(*Void); ok {
			// Since Void is an empty struct, a Type interface value containing
			// &Void{} stores (*Void, nil). Since interface equality first compares
			// the type and then the concrete value, Void is always equal.
			continue
		}

		if cpy.types[i] == spec.types[i] {
			t.Fatalf("Type at index %d is not a copy: %T == %T", i, cpy.types[i], spec.types[i])
		}
	}
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
	var foo *Struct

	if err := spec.FindType("foo", &foo); err != nil {
		// There is no struct with name foo, or there
		// are multiple possibilities.
	}

	// We've found struct foo
	fmt.Println(foo.Name)
}
