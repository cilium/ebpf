package btf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
	qt "github.com/frankban/quicktest"
)

func vmlinuxSpec(tb testing.TB) *Spec {
	tb.Helper()

	// /sys/kernel/btf was introduced in 341dfcf8d78e ("btf: expose BTF info
	// through sysfs"), which shipped in Linux 5.4.
	testutils.SkipOnOldKernel(tb, "5.4", "vmlinux BTF in sysfs")

	spec, fallback, err := kernelSpec()
	if err != nil {
		tb.Fatal(err)
	}
	if fallback {
		tb.Fatal("/sys/kernel/btf/vmlinux is not available")
	}
	return spec.Copy()
}

type specAndRawBTF struct {
	raw  []byte
	spec *Spec
}

var vmlinuxTestdata = internal.Memoize(func() (specAndRawBTF, error) {
	b, err := internal.ReadAllCompressed("testdata/vmlinux.btf.gz")
	if err != nil {
		return specAndRawBTF{}, err
	}

	spec, err := loadRawSpec(bytes.NewReader(b), binary.LittleEndian, nil)
	if err != nil {
		return specAndRawBTF{}, err
	}

	return specAndRawBTF{b, spec}, nil
})

func vmlinuxTestdataReader(tb testing.TB) *bytes.Reader {
	tb.Helper()

	td, err := vmlinuxTestdata()
	if err != nil {
		tb.Fatal(err)
	}

	return bytes.NewReader(td.raw)
}

func vmlinuxTestdataSpec(tb testing.TB) *Spec {
	tb.Helper()

	td, err := vmlinuxTestdata()
	if err != nil {
		tb.Fatal(err)
	}

	return td.spec.Copy()
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
	spec := vmlinuxTestdataSpec(t)

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

	// It's valid to pass a *Type to TypeByName.
	typ := Type(iphdr2)
	if err := spec.TypeByName("iphdr", &typ); err != nil {
		t.Fatal("Can't look up using *Type:", err)
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
	rd := vmlinuxTestdataReader(b)
	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		if _, err := rd.Seek(0, io.SeekStart); err != nil {
			b.Fatal(err)
		}

		if _, err := loadRawSpec(rd, binary.LittleEndian, nil); err != nil {
			b.Fatal("Can't load BTF:", err)
		}
	}
}

func TestParseCurrentKernelBTF(t *testing.T) {
	spec := vmlinuxSpec(t)

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
	})
}

func TestVerifierError(t *testing.T) {
	_, err := NewHandle(&Builder{})
	testutils.SkipIfNotSupported(t, err)
	var ve *internal.VerifierError
	if !errors.As(err, &ve) {
		t.Fatalf("expected a VerifierError, got: %v", err)
	}

	if ve.Truncated {
		t.Fatalf("expected non-truncated verifier log: %v", err)
	}
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
	bo := guessRawBTFByteOrder(vmlinuxTestdataReader(t))
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

func TestSpecTypeByID(t *testing.T) {
	_, err := newSpec().TypeByID(0)
	qt.Assert(t, err, qt.IsNil)

	_, err = newSpec().TypeByID(1)
	qt.Assert(t, err, qt.ErrorIs, ErrNotFound)
}

func TestHaveBTF(t *testing.T) {
	testutils.CheckFeatureTest(t, haveBTF)
}

func TestHaveMapBTF(t *testing.T) {
	testutils.CheckFeatureTest(t, haveMapBTF)
}

func TestHaveProgBTF(t *testing.T) {
	testutils.CheckFeatureTest(t, haveProgBTF)
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
	types := []Type{(*Void)(nil), &Int{Size: 4}, &Int{Size: 2}}

	b, err := NewBuilder(types[1:])
	if err != nil {
		t.Fatal(err)
	}

	raw, err := b.Marshal(nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	spec, err := LoadSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}

	iter := spec.Iterate()

	for i, typ := range types {
		if !iter.Next() {
			t.Fatal("Iterator ended early at item", i)
		}

		qt.Assert(t, iter.Type, qt.DeepEquals, typ)
	}

	if iter.Next() {
		t.Fatalf("Iterator yielded too many items: %p (%[1]T)", iter.Type)
	}
}

func TestLoadSplitSpecFromReader(t *testing.T) {
	spec := vmlinuxTestdataSpec(t)

	f, err := os.Open("testdata/btf_testmod.btf")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	splitSpec, err := LoadSplitSpecFromReader(f, spec)
	if err != nil {
		t.Fatal(err)
	}

	typ, err := splitSpec.AnyTypeByName("bpf_testmod_init")
	if err != nil {
		t.Fatal(err)
	}
	typeID, err := splitSpec.TypeID(typ)
	if err != nil {
		t.Fatal(err)
	}

	typeByID, err := splitSpec.TypeByID(typeID)
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, typeByID, qt.Equals, typ)

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
		t.Fatalf("Return type of 'bpf_testmod_init()' (%s) does not match 'int' type (%s)",
			fnProto.Return, intType)
	}

	// Check that copied split-BTF's spec has correct type indexing
	splitSpecCopy := splitSpec.Copy()
	copyType, err := splitSpecCopy.AnyTypeByName("bpf_testmod_init")
	if err != nil {
		t.Fatal(err)
	}
	copyTypeID, err := splitSpecCopy.TypeID(copyType)
	if err != nil {
		t.Fatal(err)
	}
	if copyTypeID != typeID {
		t.Fatalf("'bpf_testmod_init` type ID (%d) does not match copied spec's (%d)",
			typeID, copyTypeID)
	}
}

func TestFixupDatasecLayout(t *testing.T) {
	ds := &Datasec{
		Size: 0, // Populated by fixup.
		Vars: []VarSecinfo{
			{Type: &Var{Type: &Int{Size: 4}}},
			{Type: &Var{Type: &Int{Size: 1}}},
			{Type: &Var{Type: &Int{Size: 1}}},
			{Type: &Var{Type: &Int{Size: 2}}},
			{Type: &Var{Type: &Int{Size: 16}}},
			{Type: &Var{Type: &Int{Size: 8}}},
		},
	}

	qt.Assert(t, fixupDatasecLayout(ds), qt.IsNil)

	qt.Assert(t, ds.Size, qt.Equals, uint32(40))
	qt.Assert(t, ds.Vars[0].Offset, qt.Equals, uint32(0))
	qt.Assert(t, ds.Vars[1].Offset, qt.Equals, uint32(4))
	qt.Assert(t, ds.Vars[2].Offset, qt.Equals, uint32(5))
	qt.Assert(t, ds.Vars[3].Offset, qt.Equals, uint32(6))
	qt.Assert(t, ds.Vars[4].Offset, qt.Equals, uint32(16))
	qt.Assert(t, ds.Vars[5].Offset, qt.Equals, uint32(32))
}

func BenchmarkSpecCopy(b *testing.B) {
	spec := vmlinuxTestdataSpec(b)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		spec.Copy()
	}
}
