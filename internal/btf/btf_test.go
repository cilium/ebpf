package btf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

var vmlinux struct {
	sync.Once
	err error
	raw []byte
}

func readVmLinux(tb testing.TB) *bytes.Reader {
	tb.Helper()

	vmlinux.Do(func() {
		vmlinux.raw, vmlinux.err = internal.ReadAllCompressed("testdata/vmlinux-btf.gz")
	})

	if vmlinux.err != nil {
		tb.Fatal(vmlinux.err)
	}

	return bytes.NewReader(vmlinux.raw)
}

func TestFindType(t *testing.T) {
	spec, err := loadRawSpec(readVmLinux(t), binary.LittleEndian, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	for _, typ := range []interface{}{
		nil,
		Struct{},
		&Struct{},
		[]Struct{},
		&[]Struct{},
		map[int]Struct{},
		&map[int]Struct{},
		int(0),
		new(int),
	} {
		t.Run(fmt.Sprintf("%T", typ), func(t *testing.T) {
			// spec.FindType MUST fail if typ is not a non-nil **T, where T satisfies btf.Type.
			if err := spec.FindType("iphdr", typ); err == nil {
				t.Fatalf("FindType does not fail with type %T", typ)
			}
		})
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

	for _, m := range iphdr1.Members {
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
	rd := readVmLinux(b)
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
