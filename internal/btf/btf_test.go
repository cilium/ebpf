package btf

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

func parseVMLinuxBTF(tb testing.TB) (*Spec, error) {
	fh, err := os.Open("testdata/vmlinux-btf.gz")
	if err != nil {
		tb.Fatal(err)
	}
	defer fh.Close()

	rd, err := gzip.NewReader(fh)
	if err != nil {
		tb.Fatal(err)
	}

	spec, err := loadRawSpec(rd, binary.LittleEndian, nil, nil)
	if err != nil {
		tb.Fatal("Can't load BTF:", err)
	}

	return spec, nil
}

func parseELFBTF(tb testing.TB, file string) *Spec {
	fh, err := os.Open(file)
	if err != nil {
		tb.Fatal(err)
	}
	defer fh.Close()

	spec, err := LoadSpecFromReader(fh)
	if err != nil {
		tb.Fatal("Can't load BTF:", err)
	}

	return spec
}

func TestAnyTypesByName(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/relocs-*.elf"), func(t *testing.T, file string) {
		spec := parseELFBTF(t, file)

		types, err := spec.AnyTypesByName("ambiguous")
		if err != nil {
			t.Fatal(err)
		}

		if len(types) != 2 {
			t.Fatalf("expected to receive exactly 2 types from querying ambiguous type, got: %v", types)
		}

		types, err = spec.AnyTypesByName("ambiguous___flavour")
		if err != nil {
			t.Fatal(err)
		}

		if len(types) != 1 {
			t.Fatalf("expected to receive exactly 1 type from querying ambiguous flavour, got: %v", types)
		}
	})
}

func TestTypeByName(t *testing.T) {
	spec, err := parseVMLinuxBTF(t)
	if err != nil {
		t.Fatal(err)
	}

	// spec.TypeByName MUST fail if typ is a nil btf.Type.
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
		if err := spec.TypeByName("iphdr", typ); err == nil {
			t.Fatalf("TypeByName does not fail with type %T", typ)
		}
	}

	// spec.TypeByName MUST return the same address for multiple calls with the same type name.
	var iphdr1, iphdr2 *Struct
	if err := spec.TypeByName("iphdr", &iphdr1); err != nil {
		t.Fatal(err)
	}
	if err := spec.TypeByName("iphdr", &iphdr2); err != nil {
		t.Fatal(err)
	}

	if iphdr1 != iphdr2 {
		t.Fatal("multiple TypeByName calls for `iphdr` name do not return the same addresses")
	}
}

func TestParseVmlinux(t *testing.T) {
	spec, err := parseVMLinuxBTF(t)
	if err != nil {
		t.Fatal(err)
	}

	var iphdr *Struct
	err = spec.TypeByName("iphdr", &iphdr)
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

func BenchmarkParseVmlinux(b *testing.B) {
	fh, err := os.Open("testdata/vmlinux-btf.gz")
	if err != nil {
		b.Fatal(err)
	}
	defer fh.Close()

	gr, err := gzip.NewReader(fh)
	if err != nil {
		b.Fatal(err)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(gr); err != nil {
		b.Fatal(err)
	}
	rd := bytes.NewReader(buf.Bytes())

	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		if _, err := rd.Seek(0, io.SeekStart); err != nil {
			b.Fatal(err)
		}

		if _, err := loadRawSpec(rd, binary.LittleEndian, nil, nil); err != nil {
			b.Fatal("Can't load BTF:", err)
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
		spec := parseELFBTF(t, file)

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

		vt, err := spec.TypeByID(0)
		if err != nil {
			t.Error("Can't retrieve void type by ID:", err)
		}
		if _, ok := vt.(*Void); !ok {
			t.Errorf("Expected Void for type id 0, but got: %T", vt)
		}

		var bpfMapDef *Struct
		if err := spec.TypeByName("bpf_map_def", &bpfMapDef); err != nil {
			t.Error("Can't find bpf_map_def:", err)
		}

		var tmp *Void
		if err := spec.TypeByName("totally_bogus_type", &tmp); !errors.Is(err, ErrNotFound) {
			t.Error("TypeByName doesn't return ErrNotFound:", err)
		}

		var fn *Func
		if err := spec.TypeByName("global_fn", &fn); err != nil {
			t.Error("Can't find global_fn():", err)
		} else {
			if fn.Linkage != GlobalFunc {
				t.Error("Expected global linkage:", fn)
			}
		}

		var v *Var
		if err := spec.TypeByName("key3", &v); err != nil {
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
	spec := parseELFBTF(t, "../../testdata/loader-el.elf")

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

func ExampleSpec_TypeByName() {
	// Acquire a Spec via one of its constructors.
	spec := new(Spec)

	// Declare a variable of the desired type
	var foo *Struct

	if err := spec.TypeByName("foo", &foo); err != nil {
		// There is no struct with name foo, or there
		// are multiple possibilities.
	}

	// We've found struct foo
	fmt.Println(foo.Name)
}
