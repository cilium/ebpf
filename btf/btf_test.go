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

func readVMLinux(tb testing.TB) *bytes.Reader {
	tb.Helper()

	vmlinux.Do(func() {
		vmlinux.raw, vmlinux.err = internal.ReadAllCompressed("testdata/vmlinux-btf.gz")
	})

	if vmlinux.err != nil {
		tb.Fatal(vmlinux.err)
	}

	return bytes.NewReader(vmlinux.raw)
}

func parseELFBTF(tb testing.TB, file string) *Spec {
	tb.Helper()

	spec, err := LoadSpec(file)
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

		if len(types) != 1 {
			t.Fatalf("expected to receive exactly 1 types from querying ambiguous type, got: %v", types)
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

func TestTypeByNameAmbiguous(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "testdata/relocs-*.elf"), func(t *testing.T, file string) {
		spec := parseELFBTF(t, file)

		var typ *Struct
		if err := spec.TypeByName("ambiguous", &typ); err != nil {
			t.Fatal(err)
		}

		if name := typ.TypeName(); name != "ambiguous" {
			t.Fatal("expected type name 'ambiguous', got:", name)
		}

		if err := spec.TypeByName("ambiguous___flavour", &typ); err != nil {
			t.Fatal(err)
		}

		if name := typ.TypeName(); name != "ambiguous___flavour" {
			t.Fatal("expected type name 'ambiguous___flavour', got:", name)
		}
	})
}

func TestTypeByName(t *testing.T) {
	spec, err := LoadSpecFromReader(readVMLinux(t))
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
			// spec.TypeByName MUST fail if typ is a nil btf.Type.
			if err := spec.TypeByName("iphdr", typ); err == nil {
				t.Fatalf("TypeByName does not fail with type %T", typ)
			}
		})
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

	// Excerpt from linux/ip.h, https://elixir.bootlin.com/linux/latest/A/ident/iphdr
	//
	// struct iphdr {
	// #if defined(__LITTLE_ENDIAN_BITFIELD)
	//     __u8 ihl:4, version:4;
	// #elif defined (__BIG_ENDIAN_BITFIELD)
	//     __u8 version:4, ihl:4;
	// #else
	//     ...
	// }
	//
	// The BTF we test against is for little endian.
	m := iphdr1.Members[1]
	if m.Name != "version" {
		t.Fatal("Expected version as the second member, got", m.Name)
	}
	td, ok := m.Type.(*Typedef)
	if !ok {
		t.Fatalf("version member of iphdr should be a __u8 typedef: actual: %T", m.Type)
	}
	u8, ok := td.Type.(*Int)
	if !ok {
		t.Fatalf("__u8 typedef should point to an Int type: actual: %T", td.Type)
	}
	if m.BitfieldSize != 4 {
		t.Fatalf("incorrect bitfield size: expected: 4 actual: %d", m.BitfieldSize)
	}
	if u8.Encoding != 0 {
		t.Fatalf("incorrect encoding of an __u8 int: expected: 0 actual: %x", u8.Encoding)
	}
	if m.Offset != 4 {
		t.Fatalf("incorrect bitfield offset: expected: 4 actual: %d", m.Offset)
	}
}

func BenchmarkParseVmlinux(b *testing.B) {
	rd := readVMLinux(b)
	b.ReportAllocs()
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
	spec, err := LoadKernelSpec()
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't load BTF:", err)
	}

	if len(spec.namedTypes) == 0 {
		t.Fatal("Empty kernel BTF")
	}

	totalBytes := 0
	distinct := 0
	seen := make(map[string]bool)
	for _, str := range spec.strings.strings {
		totalBytes += len(str)
		if !seen[str] {
			distinct++
			seen[str] = true
		}
	}
	t.Logf("%d strings total, %d distinct", len(spec.strings.strings), distinct)
	t.Logf("Average string size: %.0f", float64(totalBytes)/float64(len(spec.strings.strings)))
}

func TestFindVMLinux(t *testing.T) {
	file, err := findVMLinux()
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't find vmlinux:", err)
	}
	defer file.Close()

	spec, err := loadSpecFromELF(file)
	if err != nil {
		t.Fatal("Can't load BTF:", err)
	}

	if len(spec.namedTypes) == 0 {
		t.Fatal("Empty kernel BTF")
	}
}

func TestLoadSpecFromElf(t *testing.T) {
	testutils.Files(t, testutils.Glob(t, "../testdata/loader-e*.elf"), func(t *testing.T, file string) {
		spec := parseELFBTF(t, file)

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

func TestGuessBTFByteOrder(t *testing.T) {
	bo := guessRawBTFByteOrder(readVMLinux(t))
	if bo != binary.LittleEndian {
		t.Fatalf("Guessed %s instead of %s", bo, binary.LittleEndian)
	}
}

func TestSpecCopy(t *testing.T) {
	spec := parseELFBTF(t, "../testdata/loader-el.elf")

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

func TestTypesIterator(t *testing.T) {
	spec, err := LoadSpecFromReader(readVMLinux(t))
	if err != nil {
		t.Fatal(err)
	}

	if len(spec.types) < 1 {
		t.Fatal("Not enough types")
	}

	// Assertion that 'iphdr' type exists within the spec
	_, err = spec.AnyTypeByName("iphdr")
	if err != nil {
		t.Fatalf("Failed to find 'iphdr' type by name: %s", err)
	}

	found := false
	count := 0

	iter := spec.Iterate()
	for iter.Next() {
		if !found && iter.Type.TypeName() == "iphdr" {
			found = true
		}
		count += 1
	}

	if l := len(spec.types); l != count {
		t.Fatalf("Failed to iterate over all types (%d vs %d)", l, count)
	}
	if !found {
		t.Fatal("Cannot find 'iphdr' type")
	}
}

func TestLoadSplitSpecFromReader(t *testing.T) {
	spec, err := LoadSpecFromReader(readVMLinux(t))
	if err != nil {
		t.Fatal(err)
	}

	f, err := os.Open("testdata/xt_nat")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	splitSpec, err := LoadSplitSpecFromReader(f, spec)
	if err != nil {
		t.Fatal(err)
	}

	// net/netfilter/xt_nat.c:static int xt_nat_checkentry(const struct xt_tgchk_param *par)
	typ, err := splitSpec.AnyTypeByName("xt_nat_checkentry")
	if err != nil {
		t.Fatal(err)
	}
	typeID, err := splitSpec.TypeID(typ)
	if err != nil {
		t.Fatal(err)
	}
	fnType := typ.(*Func)
	fnProto := fnType.Type.(*FuncProto)

	// 'int' is defined in the base BTF...
	intType, err := spec.AnyTypeByName("int")
	if err != nil {
		t.Fatal(err)
	}
	// ... but not in the split BTF
	_, err = splitSpec.AnyTypeByName("int")
	if err == nil {
		t.Fatal("'int' is not supposed to be found in the split BTF")
	}

	if fnProto.Return != intType {
		t.Fatalf("Return type of 'xt_nat_checkentry()' (%s) does not match 'int' type (%s)",
			fnProto.Return, intType)
	}

	// Check that copied split-BTF's spec has correct type indexing
	splitSpecCopy := splitSpec.Copy()
	copyType, err := splitSpecCopy.AnyTypesByName("xt_nat_checkentry")
	if err != nil {
		t.Fatal(err)
	}
	if copyTypeId, found := splitSpecCopy.typeIDs[copyType[0]]; typeID != copyTypeId {
		t.Fatalf("'xt_nat_checkentry` type ID (%d) does not match copied spec's (%d %v)",
			typeID, copyTypeId, found)
	}

}
