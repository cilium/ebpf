package ebpf

import (
	"encoding/binary"
	"runtime"
	"structs"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

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
	qt.Assert(t, qt.DeepEquals(cpy.Variables["var_rodata"].Value, wantb))

	// Verify that the original underlying MapSpec was not modified.
	zero := make([]byte, 4)
	qt.Assert(t, qt.DeepEquals(spec.Maps[".rodata"].Contents[0].Value.([]byte), zero))

	// Check that modifications to the VariableSpec's Type don't affect the
	// underlying MapSpec's type information on either the original or the copy.
	cpy.Variables["var_rodata"].Type.Name = "modified"
	spec.Variables["var_rodata"].Type.Name = "modified"

	qt.Assert(t, qt.Equals(cpy.Maps[".rodata"].Value.(*btf.Datasec).Vars[0].Type.(*btf.Var).Name, "var_rodata"))
	qt.Assert(t, qt.Equals(spec.Maps[".rodata"].Value.(*btf.Datasec).Vars[0].Type.(*btf.Var).Name, "var_rodata"))
}

func TestVariableSpecEmptyValue(t *testing.T) {
	spec := &VariableSpec{
		Type: &btf.Var{
			Type: &btf.Int{
				Size: 4,
			},
		},
	}

	value := uint32(0x12345678)
	raw, err := binary.Append(nil, internal.NativeEndian, value)
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.IsNotNil(spec.Get(new(uint32))))

	qt.Assert(t, qt.IsNotNil(spec.Set(uint64(0))), qt.Commentf("Setting a value of incorrect size should fail"))

	qt.Assert(t, qt.IsNil(spec.Set(value)))
	qt.Assert(t, qt.DeepEquals(spec.Value, raw))

	spec.Value = nil
	spec.Type = nil
	qt.Assert(t, qt.IsNil(spec.Set(uint64(0))), qt.Commentf("Setting an empty value without a type should accept any type"))
	qt.Assert(t, qt.HasLen(spec.Value, 8))
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

	qt.Assert(t, qt.IsNil(loadAndAssign(t, spec, &obj, nil)))
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

	qt.Assert(t, qt.IsNil(loadAndAssign(t, spec, &obj, nil)))
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

	mustLoadAndAssign(t, spec, &obj, nil)

	// Expect either success or ErrNotSupported on all systems.
	u32 := uint32(0)
	if err := obj.Data.Get(&u32); err != nil {
		qt.Assert(t, qt.ErrorIs(err, ErrNotSupported))
	}

	if err := obj.Data.Set(&u32); err != nil {
		qt.Assert(t, qt.ErrorIs(err, ErrNotSupported))
	}
}

func TestVariablePointer(t *testing.T) {
	testutils.SkipIfNotSupported(t, haveMmapableMaps())

	file := testutils.NativeFile(t, "testdata/variables-%s.elf")
	spec, err := LoadCollectionSpec(file)
	qt.Assert(t, qt.IsNil(err))

	obj := struct {
		AddAtomic      *Program `ebpf:"add_atomic"`
		CheckStructPad *Program `ebpf:"check_struct_pad"`
		CheckArray     *Program `ebpf:"check_array"`

		Atomic    *Variable `ebpf:"var_atomic"`
		StructPad *Variable `ebpf:"var_struct_pad"`
		Array     *Variable `ebpf:"var_array"`
	}{}

	unsafeMemory = true
	t.Cleanup(func() {
		unsafeMemory = false
	})

	qt.Assert(t, qt.IsNil(loadAndAssign(t, spec, &obj, nil)))
	t.Cleanup(func() {
		obj.AddAtomic.Close()
		obj.CheckStructPad.Close()
		obj.CheckArray.Close()
	})

	// Bump the value by 1 using a bpf program.
	want := uint32(1338)
	a32, err := VariablePointer[atomic.Uint32](obj.Atomic)
	qt.Assert(t, qt.IsNil(err))
	a32.Store(want - 1)

	mustReturn(t, obj.AddAtomic, 0)
	qt.Assert(t, qt.Equals(a32.Load(), want))

	_, err = VariablePointer[*uint32](obj.Atomic)
	qt.Assert(t, qt.ErrorIs(err, ErrInvalidType))

	_, err = VariablePointer[struct{ _ *uint64 }](obj.StructPad)
	qt.Assert(t, qt.ErrorIs(err, ErrInvalidType))

	type S struct {
		_ structs.HostLayout
		A uint32
		B uint64
		C uint16
		D [5]byte
		E uint64
	}

	s, err := VariablePointer[S](obj.StructPad)
	qt.Assert(t, qt.IsNil(err))
	*s = S{A: 0xa, B: 0xb, C: 0xc, D: [5]byte{0xd, 0, 0, 0, 0}, E: 0xe}
	mustReturn(t, obj.CheckStructPad, 1)

	a, err := VariablePointer[[8192]byte](obj.Array)
	qt.Assert(t, qt.IsNil(err))
	a[len(a)-1] = 0xff
	mustReturn(t, obj.CheckArray, 1)
}

func TestVariablePointerError(t *testing.T) {
	testutils.SkipIfNotSupported(t, haveMmapableMaps())

	file := testutils.NativeFile(t, "testdata/variables-%s.elf")
	spec, err := LoadCollectionSpec(file)
	qt.Assert(t, qt.IsNil(err))

	obj := struct {
		Atomic *Variable `ebpf:"var_atomic"`
	}{}

	qt.Assert(t, qt.IsNil(loadAndAssign(t, spec, &obj, nil)))

	_, err = VariablePointer[atomic.Uint32](obj.Atomic)
	qt.Assert(t, qt.ErrorIs(err, ErrNotSupported))
}

func TestVariablePointerGC(t *testing.T) {
	testutils.SkipIfNotSupported(t, haveMmapableMaps())

	file := testutils.NativeFile(t, "testdata/variables-%s.elf")
	spec, err := LoadCollectionSpec(file)
	qt.Assert(t, qt.IsNil(err))

	cancel := make(chan struct{})

	type obj_s struct {
		AddAtomic *Program  `ebpf:"add_atomic"`
		Atomic    *Variable `ebpf:"var_atomic"`
		AtomicMap *Map      `ebpf:".data.atomic"`
	}

	unsafeMemory = true
	t.Cleanup(func() {
		unsafeMemory = false
	})
	var obj obj_s
	qt.Assert(t, qt.IsNil(loadAndAssign(t, spec, &obj, nil)))

	// Set cleanup on obj to get notified when it is collected.
	ogc := make(chan struct{})
	runtime.AddCleanup(&obj, func(*byte) {
		close(ogc)
	}, nil)
	mem, err := obj.AtomicMap.unsafeMemory()
	qt.Assert(t, qt.IsNil(err))
	obj.AtomicMap.Close()

	// Start a goroutine that panics if the finalizer runs before we expect it to.
	mgc := make(chan struct{})
	go func() {
		select {
		case <-mgc:
			panic("memory cleanup ran unexpectedly")
		case <-cancel:
			return
		}
	}()

	// Set cleanup on the Memory's backing array to get notified when it is
	// collected.
	runtime.AddCleanup(unsafe.SliceData(mem.b), func(*byte) {
		close(mgc)
	}, nil)

	// Pull out Program handle and Variable pointer so reference to obj is
	// dropped.
	prog := obj.AddAtomic
	t.Cleanup(func() {
		prog.Close()
	})

	a32, err := VariablePointer[atomic.Uint32](obj.Atomic)
	qt.Assert(t, qt.IsNil(err))

	// No references to obj past this point. Trigger GC and wait for the obj
	// finalizer to complete.
	runtime.GC()
	testutils.WaitChan(t, ogc, time.Second)

	// Trigger prog and read memory to ensure variable reference is still valid.
	mustReturn(t, prog, 0)
	qt.Assert(t, qt.Equals(a32.Load(), 1))

	// Close the cancel channel while holding a backing array reference to avoid
	// false-positive panics in case we get a GC cycle before the manual call to
	// runtime.GC below.
	close(cancel)
	runtime.KeepAlive(a32)

	// More GC cycles to collect the backing array. As long as the unsafe memory
	// implementation is still on SetFinalizer, this needs multiple cycles to
	// work, since finalizers can resurrect objects. 3 GCs seems to work reliably.
	runtime.GC()
	runtime.GC()
	runtime.GC()

	// Wait for backing array to be finalized.
	testutils.WaitChan(t, mgc, time.Second*5)
}
