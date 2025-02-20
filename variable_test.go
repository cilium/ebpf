package ebpf

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestVariableSpec(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/variables-%s.elf")
	spec, err := LoadCollectionSpec(file)
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNil(spec.Variables["hidden"]))
	qt.Assert(t, qt.IsNotNil(spec.Variables["weak"]))

	const want uint32 = 12345

	// Update a variable in each type of data section (.bss,.data,.rodata)
	qt.Assert(t, qt.IsNil(spec.Variables["var_bss"].Set(want)))
	qt.Assert(t, qt.IsNil(spec.Variables["var_data"].Set(want)))
	qt.Assert(t, qt.IsNil(spec.Variables["var_rodata"].Set(want)))

	var v uint32
	qt.Assert(t, qt.IsNil(spec.Variables["var_bss"].Get(&v)))
	qt.Assert(t, qt.Equals(v, want))
	qt.Assert(t, qt.IsNil(spec.Variables["var_data"].Get(&v)))
	qt.Assert(t, qt.Equals(v, want))
	qt.Assert(t, qt.IsNil(spec.Variables["var_rodata"].Get(&v)))
	qt.Assert(t, qt.Equals(v, want))

	// Composite values.
	type structT struct {
		A, B uint64
	}
	qt.Assert(t, qt.IsNil(spec.Variables["var_struct"].Set(&structT{1, 2})))

	var s structT
	qt.Assert(t, qt.IsNil(spec.Variables["var_struct"].Get(&s)))
	qt.Assert(t, qt.Equals(s, structT{1, 2}))
}

func TestVariableSpecCopy(t *testing.T) {
	file := testutils.NativeFile(t, "testdata/variables-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	cpy := spec.Copy()

	// Update a variable in a section with only a single variable (.rodata).
	const want uint32 = 0xfefefefe
	wantb := []byte{0xfe, 0xfe, 0xfe, 0xfe} // Same byte sequence regardless of endianness
	qt.Assert(t, qt.IsNil(cpy.Variables["var_rodata"].Set(want)))
	qt.Assert(t, qt.DeepEquals(cpy.Maps[".rodata"].Contents[0].Value.([]byte), wantb))

	// Verify that the original underlying MapSpec was not modified.
	zero := make([]byte, 4)
	qt.Assert(t, qt.DeepEquals(spec.Maps[".rodata"].Contents[0].Value.([]byte), zero))

	// Check that modifications to the VariableSpec's Type don't affect the
	// underlying MapSpec's type information on either the original or the copy.
	cpy.Variables["var_rodata"].Type().Name = "modified"
	spec.Variables["var_rodata"].Type().Name = "modified"

	qt.Assert(t, qt.Equals(cpy.Maps[".rodata"].Value.(*btf.Datasec).Vars[0].Type.(*btf.Var).Name, "var_rodata"))
	qt.Assert(t, qt.Equals(spec.Maps[".rodata"].Value.(*btf.Datasec).Vars[0].Type.(*btf.Var).Name, "var_rodata"))
}

func mustReturn(tb testing.TB, prog *Program, value uint32) {
	tb.Helper()

	ret, _, err := prog.Test(internal.EmptyBPFContext)
	qt.Assert(tb, qt.IsNil(err))
	qt.Assert(tb, qt.Equals(ret, value))
}

func TestVariable(t *testing.T) {
	testutils.SkipIfNotSupported(t, haveMmapableMaps())

	file := testutils.NativeFile(t, "testdata/variables-%s.elf")
	spec, err := LoadCollectionSpec(file)
	qt.Assert(t, qt.IsNil(err))

	obj := struct {
		GetBSS      *Program `ebpf:"get_bss"`
		GetData     *Program `ebpf:"get_data"`
		CheckStruct *Program `ebpf:"check_struct"`

		BSS    *Variable `ebpf:"var_bss"`
		Data   *Variable `ebpf:"var_data"`
		Struct *Variable `ebpf:"var_struct"`
		Array  *Variable `ebpf:"var_array"`
	}{}

	qt.Assert(t, qt.IsNil(spec.LoadAndAssign(&obj, nil)))
	t.Cleanup(func() {
		obj.GetBSS.Close()
		obj.GetData.Close()
		obj.CheckStruct.Close()
	})

	mustReturn(t, obj.GetBSS, 0)
	mustReturn(t, obj.GetData, 0)
	mustReturn(t, obj.CheckStruct, 0)

	want := uint32(4242424242)
	qt.Assert(t, qt.IsNil(obj.BSS.Set(want)))
	mustReturn(t, obj.GetBSS, want)
	qt.Assert(t, qt.IsNil(obj.Data.Set(want)))
	mustReturn(t, obj.GetData, want)
	qt.Assert(t, qt.IsNil(obj.Struct.Set(&struct{ A, B uint64 }{0xa, 0xb})))
	mustReturn(t, obj.CheckStruct, 1)

	// Ensure page-aligned array variable can be accessed in its entirety.
	arr := make([]byte, obj.Array.Size())
	qt.Assert(t, qt.IsNil(obj.Array.Get(arr)))
	qt.Assert(t, qt.IsNil(obj.Array.Set(arr)))

	typ := obj.BSS.Type()
	qt.Assert(t, qt.IsNotNil(typ))
	i, ok := btf.As[*btf.Int](typ.Type)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Equals(i.Size, 4))

	qt.Assert(t, qt.IsNotNil(obj.Data.Type()))
	qt.Assert(t, qt.IsNotNil(obj.Struct.Type()))
}

func TestVariableConst(t *testing.T) {
	testutils.SkipIfNotSupported(t, haveMmapableMaps())

	file := testutils.NativeFile(t, "testdata/variables-%s.elf")
	spec, err := LoadCollectionSpec(file)
	qt.Assert(t, qt.IsNil(err))

	want := uint32(12345)
	qt.Assert(t, qt.IsNil(spec.Variables["var_rodata"].Set(want)))

	obj := struct {
		GetRodata *Program  `ebpf:"get_rodata"`
		Rodata    *Variable `ebpf:"var_rodata"`
	}{}

	qt.Assert(t, qt.IsNil(spec.LoadAndAssign(&obj, nil)))
	t.Cleanup(func() {
		obj.GetRodata.Close()
	})

	var got uint32
	qt.Assert(t, qt.IsNil(obj.Rodata.Get(&got)))
	qt.Assert(t, qt.Equals(got, want))
	mustReturn(t, obj.GetRodata, want)

	qt.Assert(t, qt.IsTrue(obj.Rodata.ReadOnly()))
	qt.Assert(t, qt.ErrorIs(obj.Rodata.Set(want), ErrReadOnly))
}

func TestVariableFallback(t *testing.T) {
	// LoadAndAssign should work on Variable regardless of BPF_F_MMAPABLE support.
	file := testutils.NativeFile(t, "testdata/variables-%s.elf")
	spec, err := LoadCollectionSpec(file)
	qt.Assert(t, qt.IsNil(err))

	obj := struct {
		Data *Variable `ebpf:"var_data"`
	}{}
	qt.Assert(t, qt.IsNil(spec.LoadAndAssign(&obj, nil)))

	// Expect either success or ErrNotSupported on all systems.
	u32 := uint32(0)
	if err := obj.Data.Get(&u32); err != nil {
		qt.Assert(t, qt.ErrorIs(err, ErrNotSupported))
	}

	if err := obj.Data.Set(&u32); err != nil {
		qt.Assert(t, qt.ErrorIs(err, ErrNotSupported))
	}
}
