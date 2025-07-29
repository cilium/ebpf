package btf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

func vmlinuxSpec(tb testing.TB) *Spec {
	tb.Helper()

	// /sys/kernel/btf was introduced in 341dfcf8d78e ("btf: expose BTF info
	// through sysfs"), which shipped in Linux 5.4.
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); errors.Is(err, fs.ErrNotExist) {
		tb.Skip("No /sys/kernel/btf/vmlinux")
	}

	spec, err := LoadKernelSpec()
	if err != nil {
		tb.Fatal(err)
	}
	return spec
}

type specAndRawBTF struct {
	raw  []byte
	spec *Spec
}

var vmlinuxTestdata = sync.OnceValues(func() (specAndRawBTF, error) {
	b, err := internal.ReadAllCompressed("testdata/vmlinux.btf.gz")
	if err != nil {
		return specAndRawBTF{}, err
	}

	spec, err := loadRawSpec(b, nil)
	if err != nil {
		return specAndRawBTF{}, err
	}

	return specAndRawBTF{b, spec}, nil
})

func vmlinuxTestdataSpec(tb testing.TB) *Spec {
	tb.Helper()

	td, err := vmlinuxTestdata()
	if err != nil {
		tb.Fatal(err)
	}

	return td.spec.Copy()
}

func vmlinuxTestdataBytes(tb testing.TB) []byte {
	tb.Helper()

	td, err := vmlinuxTestdata()
	if err != nil {
		tb.Fatal(err)
	}

	return td.raw
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
	vmlinux := vmlinuxTestdataBytes(b)
	b.ReportAllocs()
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		if _, err := loadRawSpec(vmlinux, nil); err != nil {
			b.Fatal("Can't load BTF:", err)
		}
	}
}

func BenchmarkIterateVmlinux(b *testing.B) {
	vmlinux := vmlinuxTestdataBytes(b)
	b.ReportAllocs()
	b.ResetTimer()

	for range b.N {
		spec, err := loadRawSpec(vmlinux, nil)
		if err != nil {
			b.Fatal("Can't load BTF:", err)
		}

		for range spec.All() {
		}
	}
}

func TestParseCurrentKernelBTF(t *testing.T) {
	spec := vmlinuxSpec(t)

	if len(spec.offsets) == 0 {
		t.Fatal("Empty kernel BTF")
	}
}

func TestFindVMLinux(t *testing.T) {
	file, err := findVMLinux()
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't find vmlinux:", err)
	}
	defer file.Close()

	spec, err := LoadSpecFromReader(file)
	if err != nil {
		t.Fatal("Can't load BTF:", err)
	}

	if len(spec.offsets) == 0 {
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
			t.Error("Can't find key3:", err)
		} else {
			if v.Linkage != GlobalVar {
				t.Error("Expected global linkage:", v)
			}
		}
	})
}

func TestVerifierError(t *testing.T) {
	b, err := NewBuilder([]Type{&Int{Encoding: 255}})
	qt.Assert(t, qt.IsNil(err))
	_, err = NewHandle(b)
	testutils.SkipIfNotSupported(t, err)
	var ve *internal.VerifierError
	if !errors.As(err, &ve) {
		t.Fatalf("expected a VerifierError, got: %v", err)
	}
}

func TestSpecCopy(t *testing.T) {
	qt.Check(t, qt.IsNil((*Spec)(nil).Copy()))

	spec := parseELFBTF(t, "../testdata/loader-el.elf")
	cpy := spec.Copy()

	have := typesFromSpec(t, spec)
	qt.Assert(t, qt.IsTrue(len(have) > 0))

	want := typesFromSpec(t, cpy)
	qt.Assert(t, qt.HasLen(want, len(have)))

	for i := range want {
		if _, ok := have[i].(*Void); ok {
			// Since Void is an empty struct, a Type interface value containing
			// &Void{} stores (*Void, nil). Since interface equality first compares
			// the type and then the concrete value, Void is always equal.
			continue
		}

		if have[i] == want[i] {
			t.Fatalf("Type at index %d is not a copy: %T == %T", i, have[i], want[i])
		}
	}
}

func TestSpecCopyModifications(t *testing.T) {
	spec := specFromTypes(t, []Type{&Int{Name: "a", Size: 4}})

	typ, err := spec.TypeByID(1)
	qt.Assert(t, qt.IsNil(err))

	i := typ.(*Int)
	i.Name = "b"
	i.Size = 2

	cpy := spec.Copy()
	typ2, err := cpy.TypeByID(1)
	qt.Assert(t, qt.IsNil(err))
	i2 := typ2.(*Int)

	qt.Assert(t, qt.Not(qt.Equals(i2, i)), qt.Commentf("Types are distinct"))
	qt.Assert(t, qt.DeepEquals(i2, i), qt.Commentf("Modifications are preserved"))

	i.Name = "bar"
	qt.Assert(t, qt.Equals(i2.Name, "b"))
}

func TestSpecTypeByID(t *testing.T) {
	spec := specFromTypes(t, nil)

	_, err := spec.TypeByID(0)
	qt.Assert(t, qt.IsNil(err))

	_, err = spec.TypeByID(1)
	qt.Assert(t, qt.ErrorIs(err, ErrNotFound))
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

	var have []Type
	for typ, err := range spec.All() {
		qt.Assert(t, qt.IsNil(err))
		have = append(have, typ)
	}

	qt.Assert(t, qt.DeepEquals(have, types))
}

func TestLoadSplitSpec(t *testing.T) {
	spec := vmlinuxTestdataSpec(t)

	splitSpec, err := LoadSplitSpec("testdata/btf_testmod.btf", spec)
	if err != nil {
		t.Fatal(err)
	}

	var fnType *Func
	qt.Assert(t, qt.IsNil(splitSpec.TypeByName("bpf_testmod_init", &fnType)))
	typeID, err := splitSpec.TypeID(fnType)
	qt.Assert(t, qt.IsNil(err))

	typeByID, err := splitSpec.TypeByID(typeID)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(typeByID, Type(fnType)))

	fnProto := fnType.Type.(*FuncProto)
	_, err = spec.TypeID(fnProto)
	qt.Assert(t, qt.IsNil(err), qt.Commentf("FuncProto should be in base"))

	// 'int' is defined in the base BTF...
	intType, err := spec.AnyTypeByName("int")
	qt.Assert(t, qt.IsNil(err))

	// ... but not in the split BTF
	_, err = splitSpec.AnyTypeByName("int")
	qt.Assert(t, qt.ErrorIs(err, ErrNotFound))

	qt.Assert(t, qt.Equals(fnProto.Return, intType),
		qt.Commentf("types found in base of split spec should be reused"))

	fnProto.Params = []FuncParam{{"a", &Pointer{(*Void)(nil)}}}

	// The behaviour of copying a split spec is quite subtle. When initially
	// creating a split spec, types in the split base are shared. This allows
	// amortising the cost of decoding vmlinux.
	//
	// However, we currently define copying a spec to be like forking a process:
	// in-memory changes to types are preserved. After the copy finished we have
	// two fully independent states.
	//
	// For split BTF this means that we also need to copy the base and ensure
	// that future references to a modified type work correctly.
	splitSpecCopy := splitSpec.Copy()

	var fnCopyType *Func
	qt.Assert(t, qt.IsNil(splitSpecCopy.TypeByName("bpf_testmod_init", &fnCopyType)))
	qt.Assert(t, testutils.IsDeepCopy(fnCopyType, fnType))

	// Pull out a second type which refers to "int" in the base, but which hasn't
	// been inflated yet. This forces inflating int from the base.
	var str *Struct
	qt.Assert(t, qt.IsNil(splitSpecCopy.TypeByName("bpf_testmod_struct_arg_1", &str)))

	// Ensure that the int types are indeed the same.
	qt.Assert(t, qt.Equals(str.Members[0].Type, fnCopyType.Type.(*FuncProto).Return))

	copyTypeID, err := splitSpecCopy.TypeID(fnCopyType)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(copyTypeID, typeID), qt.Commentf("ID of copied type must match"))
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

	qt.Assert(t, qt.IsNil(fixupDatasecLayout(ds)))

	qt.Assert(t, qt.Equals(ds.Size, 40))
	qt.Assert(t, qt.Equals(ds.Vars[0].Offset, 0))
	qt.Assert(t, qt.Equals(ds.Vars[1].Offset, 4))
	qt.Assert(t, qt.Equals(ds.Vars[2].Offset, 5))
	qt.Assert(t, qt.Equals(ds.Vars[3].Offset, 6))
	qt.Assert(t, qt.Equals(ds.Vars[4].Offset, 16))
	qt.Assert(t, qt.Equals(ds.Vars[5].Offset, 32))
}

func TestSpecConcurrentAccess(t *testing.T) {
	spec := vmlinuxTestdataSpec(t)

	maxprocs := runtime.GOMAXPROCS(0)
	if maxprocs < 2 {
		t.Error("GOMAXPROCS is lower than 2:", maxprocs)
	}

	var cond atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < maxprocs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			n := cond.Add(1)
			for cond.Load() != int64(maxprocs) {
				// Spin to increase the chances of a race.
			}

			if n%2 == 0 {
				_, _ = spec.AnyTypeByName("gov_update_cpu_data")
			} else {
				_ = spec.Copy()
			}
		}()

		// Try to get the Goroutines scheduled and spinning.
		runtime.Gosched()
	}
	wg.Wait()
}

func TestLoadEmptyRawSpec(t *testing.T) {
	buf, err := binary.Append(nil, binary.LittleEndian, &btfHeader{
		Magic:     btfMagic,
		Version:   1,
		Flags:     0,
		HdrLen:    uint32(btfHeaderLen),
		TypeOff:   0,
		TypeLen:   0,
		StringOff: 0,
		StringLen: 0,
	})
	qt.Assert(t, qt.IsNil(err))

	_, err = loadRawSpec(buf, nil)
	qt.Assert(t, qt.IsNil(err))
}

func BenchmarkSpecCopy(b *testing.B) {
	spec := vmlinuxTestdataSpec(b)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		spec.Copy()
	}
}

func BenchmarkSpecTypeByID(b *testing.B) {
	spec := vmlinuxTestdataSpec(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := spec.TypeByID(1)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkInspektorGadget(b *testing.B) {
	// This benchmark is the baseline for what Inspektor Gadget loads for a
	// common configuration.
	types := []string{
		"pt_regs",
		"file",
		"inode",
		"super_block",
		"socket",
		"syscall_trace_enter",
		"task_struct",
		"nsproxy",
		"mnt_namespace",
		// "fanotify_event",
		"pid",
		"trace_event_raw_sched_process_exec",
		"fs_struct",
		"path",
		"mount",
		"qstr",
		"vfsmount",
		"dentry",
		// "bpf_func_id",
		"mm_struct",
		"syscall_trace_exit",
		"linux_binprm",
		"sock",
		"net",
		"inet_sock",
	}

	vmlinux, err := internal.ReadAllCompressed("testdata/vmlinux.btf.gz")
	qt.Assert(b, qt.IsNil(err))

	var rd bytes.Reader

	b.ResetTimer()

	for range b.N {
		rd.Reset(vmlinux)
		spec, err := LoadSpecFromReader(&rd)
		if err != nil {
			b.Fatal(err)
		}

		var s *Struct
		for _, name := range types {
			if err := spec.TypeByName(name, &s); err != nil {
				b.Fatal(name, err)
			}
		}
	}
}
