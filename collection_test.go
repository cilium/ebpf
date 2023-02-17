package ebpf

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/testutils/fdtrace"
	qt "github.com/frankban/quicktest"
)

func TestMain(m *testing.M) {
	fdtrace.TestMain(m)
}

func TestCollectionSpecNotModified(t *testing.T) {
	cs := CollectionSpec{
		Maps: map[string]*MapSpec{
			"my-map": {
				Type:       Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
			},
		},
		Programs: map[string]*ProgramSpec{
			"test": {
				Type: SocketFilter,
				Instructions: asm.Instructions{
					asm.LoadImm(asm.R1, 0, asm.DWord).WithReference("my-map"),
					asm.LoadImm(asm.R0, 0, asm.DWord),
					asm.Return(),
				},
				License: "MIT",
			},
		},
	}

	coll, err := NewCollection(&cs)
	if err != nil {
		t.Fatal(err)
	}
	coll.Close()

	if cs.Programs["test"].Instructions[0].Constant != 0 {
		t.Error("Creating a collection modifies input spec")
	}
}

func TestCollectionSpecCopy(t *testing.T) {
	cs := &CollectionSpec{
		Maps: map[string]*MapSpec{
			"my-map": {
				Type:       Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
			},
		},
		Programs: map[string]*ProgramSpec{
			"test": {
				Type: SocketFilter,
				Instructions: asm.Instructions{
					asm.LoadMapPtr(asm.R1, 0),
					asm.LoadImm(asm.R0, 0, asm.DWord),
					asm.Return(),
				},
				License: "MIT",
			},
		},
		Types: &btf.Spec{},
	}
	cpy := cs.Copy()

	if cpy == cs {
		t.Error("Copy returned the same pointner")
	}

	if cpy.Maps["my-map"] == cs.Maps["my-map"] {
		t.Error("Copy returned same Maps")
	}

	if cpy.Programs["test"] == cs.Programs["test"] {
		t.Error("Copy returned same Programs")
	}

	if cpy.Types != cs.Types {
		t.Error("Copy returned different Types")
	}
}

func TestCollectionSpecLoadCopy(t *testing.T) {
	file := fmt.Sprintf("testdata/loader-%s.elf", internal.ClangEndian)
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	spec2 := spec.Copy()

	var objs struct {
		Prog *Program `ebpf:"xdp_prog"`
	}

	err = spec.LoadAndAssign(&objs, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Loading original spec:", err)
	}
	defer objs.Prog.Close()

	if err := spec2.LoadAndAssign(&objs, nil); err != nil {
		t.Fatal("Loading copied spec:", err)
	}
	defer objs.Prog.Close()
}

func TestCollectionSpecRewriteMaps(t *testing.T) {
	insns := asm.Instructions{
		// R1 map
		asm.LoadMapPtr(asm.R1, 0).WithReference("test-map"),
		// R2 key
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -4),
		asm.StoreImm(asm.R2, 0, 0, asm.Word),
		// Lookup map[0]
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "ret"),
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Word),
		asm.Return().WithSymbol("ret"),
	}

	cs := &CollectionSpec{
		Maps: map[string]*MapSpec{
			"test-map": {
				Type:       Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
			},
		},
		Programs: map[string]*ProgramSpec{
			"test-prog": {
				Type:         SocketFilter,
				Instructions: insns,
				License:      "MIT",
			},
		},
	}

	// Override the map with another one
	newMap, err := NewMap(cs.Maps["test-map"])
	if err != nil {
		t.Fatal(err)
	}
	defer newMap.Close()

	err = newMap.Put(uint32(0), uint32(2))
	if err != nil {
		t.Fatal(err)
	}

	err = cs.RewriteMaps(map[string]*Map{
		"test-map": newMap,
	})
	if err != nil {
		t.Fatal(err)
	}

	if cs.Maps["test-map"] != nil {
		t.Error("RewriteMaps doesn't remove map from CollectionSpec.Maps")
	}

	coll, err := NewCollection(cs)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()

	ret, _, err := coll.Programs["test-prog"].Test(internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 2 {
		t.Fatal("new / override map not used")
	}
}

func TestCollectionSpecMapReplacements(t *testing.T) {
	insns := asm.Instructions{
		// R1 map
		asm.LoadMapPtr(asm.R1, 0).WithReference("test-map"),
		// R2 key
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -4),
		asm.StoreImm(asm.R2, 0, 0, asm.Word),
		// Lookup map[0]
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "ret"),
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Word),
		asm.Return().WithSymbol("ret"),
	}

	cs := &CollectionSpec{
		Maps: map[string]*MapSpec{
			"test-map": {
				Type:       Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
			},
		},
		Programs: map[string]*ProgramSpec{
			"test-prog": {
				Type:         SocketFilter,
				Instructions: insns,
				License:      "MIT",
			},
		},
	}

	// Replace the map with another one
	newMap, err := NewMap(cs.Maps["test-map"])
	if err != nil {
		t.Fatal(err)
	}
	defer newMap.Close()

	err = newMap.Put(uint32(0), uint32(2))
	if err != nil {
		t.Fatal(err)
	}

	coll, err := NewCollectionWithOptions(cs, CollectionOptions{
		MapReplacements: map[string]*Map{
			"test-map": newMap,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()

	ret, _, err := coll.Programs["test-prog"].Test(internal.EmptyBPFContext)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 2 {
		t.Fatal("new / override map not used")
	}

	// Check that newMap isn't closed when the collection is closed
	coll.Close()
	err = newMap.Put(uint32(0), uint32(3))
	if err != nil {
		t.Fatalf("failed to update replaced map: %s", err)
	}
}
func TestCollectionSpecMapReplacements_NonExistingMap(t *testing.T) {
	cs := &CollectionSpec{
		Maps: map[string]*MapSpec{
			"test-map": {
				Type:       Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
			},
		},
	}

	// Override non-existing map
	newMap, err := NewMap(cs.Maps["test-map"])
	if err != nil {
		t.Fatal(err)
	}
	defer newMap.Close()

	coll, err := NewCollectionWithOptions(cs, CollectionOptions{
		MapReplacements: map[string]*Map{
			"non-existing-map": newMap,
		},
	})
	if err == nil {
		coll.Close()
		t.Fatal("Overriding a non existing map did not fail")
	}
}

func TestCollectionSpecMapReplacements_SpecMismatch(t *testing.T) {
	cs := &CollectionSpec{
		Maps: map[string]*MapSpec{
			"test-map": {
				Type:       Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
			},
		},
	}

	// Override map with mismatching spec
	newMap, err := NewMap(&MapSpec{
		Type:       Array,
		KeySize:    4,
		ValueSize:  8, // this is different
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Map fd is duplicated by MapReplacements, this one can be safely closed.
	defer newMap.Close()

	coll, err := NewCollectionWithOptions(cs, CollectionOptions{
		MapReplacements: map[string]*Map{
			"test-map": newMap,
		},
	})
	if err == nil {
		coll.Close()
		t.Fatal("Overriding a map with a mismatching spec did not fail")
	}
	if !errors.Is(err, ErrMapIncompatible) {
		t.Fatalf("Overriding a map with a mismatching spec failed with the wrong error")
	}
}

func TestCollectionRewriteConstants(t *testing.T) {
	cs := &CollectionSpec{
		Maps: map[string]*MapSpec{
			".rodata": {
				Type:       Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
				Value: &btf.Datasec{
					Vars: []btf.VarSecinfo{
						{
							Type: &btf.Var{
								Name: "the_constant",
								Type: &btf.Int{Size: 4},
							},
							Offset: 0,
							Size:   4,
						},
					},
				},
				Contents: []MapKV{
					{Key: uint32(0), Value: []byte{1, 1, 1, 1}},
				},
			},
		},
	}

	err := cs.RewriteConstants(map[string]interface{}{
		"fake_constant_one": uint32(1),
		"fake_constant_two": uint32(2),
	})
	qt.Assert(t, err, qt.IsNotNil, qt.Commentf("RewriteConstants did not fail"))

	var mErr *MissingConstantsError
	if !errors.As(err, &mErr) {
		t.Fatal("Error doesn't wrap MissingConstantsError:", err)
	}
	qt.Assert(t, mErr.Constants, qt.ContentEquals, []string{"fake_constant_one", "fake_constant_two"})

	err = cs.RewriteConstants(map[string]interface{}{
		"the_constant": uint32(0x42424242),
	})
	qt.Assert(t, err, qt.IsNil)
	qt.Assert(t, cs.Maps[".rodata"].Contents[0].Value, qt.ContentEquals, []byte{0x42, 0x42, 0x42, 0x42})
}

func TestCollectionSpec_LoadAndAssign_LazyLoading(t *testing.T) {
	spec := &CollectionSpec{
		Maps: map[string]*MapSpec{
			"valid": {
				Type:       Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
			},
			"bogus": {
				Type:       Array,
				MaxEntries: 0,
			},
		},
		Programs: map[string]*ProgramSpec{
			"valid": {
				Type: SocketFilter,
				Instructions: asm.Instructions{
					asm.LoadImm(asm.R0, 0, asm.DWord),
					asm.Return(),
				},
				License: "MIT",
			},
			"bogus": {
				Type: SocketFilter,
				Instructions: asm.Instructions{
					// Undefined return value is rejected
					asm.Return(),
				},
				License: "MIT",
			},
		},
	}

	var objs struct {
		Prog *Program `ebpf:"valid"`
		Map  *Map     `ebpf:"valid"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		t.Fatal("Assign loads a map or program that isn't requested in the struct:", err)
	}
	defer objs.Prog.Close()
	defer objs.Map.Close()

	if objs.Prog == nil {
		t.Error("Program is nil")
	}

	if objs.Map == nil {
		t.Error("Map is nil")
	}
}

func TestCollectionAssign(t *testing.T) {
	var specs struct {
		Program *ProgramSpec `ebpf:"prog1"`
		Map     *MapSpec     `ebpf:"map1"`
	}

	mapSpec := &MapSpec{
		Type:       Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	progSpec := &ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	}

	cs := &CollectionSpec{
		Maps: map[string]*MapSpec{
			"map1": mapSpec,
		},
		Programs: map[string]*ProgramSpec{
			"prog1": progSpec,
		},
	}

	if err := cs.Assign(&specs); err != nil {
		t.Fatal("Can't assign spec:", err)
	}

	if specs.Program != progSpec {
		t.Fatalf("Expected Program to be %p, got %p", progSpec, specs.Program)
	}

	if specs.Map != mapSpec {
		t.Fatalf("Expected Map to be %p, got %p", mapSpec, specs.Map)
	}

	if err := cs.Assign(new(int)); err == nil {
		t.Fatal("Assign allows to besides *struct")
	}

	if err := cs.Assign(new(struct{ Foo int })); err != nil {
		t.Fatal("Assign doesn't ignore untagged fields")
	}

	unexported := new(struct {
		foo *MapSpec `ebpf:"map1"`
	})

	if err := cs.Assign(unexported); err == nil {
		t.Error("Assign should return an error on unexported fields")
	}
}

func TestAssignValues(t *testing.T) {
	zero := func(t reflect.Type, name string) (interface{}, error) {
		return reflect.Zero(t).Interface(), nil
	}

	type t1 struct {
		Bar int `ebpf:"bar"`
	}

	type t2 struct {
		t1
		Foo int `ebpf:"foo"`
	}

	type t2ptr struct {
		*t1
		Foo int `ebpf:"foo"`
	}

	invalid := []struct {
		name string
		to   interface{}
	}{
		{"non-struct", 1},
		{"non-pointer struct", t1{}},
		{"pointer to non-struct", new(int)},
		{"embedded nil pointer", &t2ptr{}},
		{"unexported field", new(struct {
			foo int `ebpf:"foo"`
		})},
		{"identical tag", new(struct {
			Foo1 int `ebpf:"foo"`
			Foo2 int `ebpf:"foo"`
		})},
	}

	for _, testcase := range invalid {
		t.Run(testcase.name, func(t *testing.T) {
			if err := assignValues(testcase.to, zero); err == nil {
				t.Fatal("assignValues didn't return an error")
			} else {
				t.Log(err)
			}
		})
	}

	valid := []struct {
		name string
		to   interface{}
	}{
		{"pointer to struct", new(t1)},
		{"embedded struct", new(t2)},
		{"embedded struct pointer", &t2ptr{t1: new(t1)}},
		{"untagged field", new(struct{ Foo int })},
	}

	for _, testcase := range valid {
		t.Run(testcase.name, func(t *testing.T) {
			if err := assignValues(testcase.to, zero); err != nil {
				t.Fatal("assignValues returned", err)
			}
		})
	}

}

func TestIncompleteLoadAndAssign(t *testing.T) {
	spec := &CollectionSpec{
		Programs: map[string]*ProgramSpec{
			"valid": {
				Type: SocketFilter,
				Instructions: asm.Instructions{
					asm.LoadImm(asm.R0, 0, asm.DWord),
					asm.Return(),
				},
				License: "MIT",
			},
			"invalid": {
				Type: SocketFilter,
				Instructions: asm.Instructions{
					asm.Return(),
				},
				License: "MIT",
			},
		},
	}

	s := struct {
		// Assignment to Valid should execute and succeed.
		Valid *Program `ebpf:"valid"`
		// Assignment to Invalid should fail and cause Valid's fd to be closed.
		Invalid *Program `ebpf:"invalid"`
	}{}

	if err := spec.LoadAndAssign(&s, nil); err == nil {
		t.Fatal("expected error loading invalid ProgramSpec")
	}

	if s.Valid == nil {
		t.Fatal("expected valid prog to be non-nil")
	}

	if fd := s.Valid.FD(); fd != -1 {
		t.Fatal("expected valid prog to have closed fd -1, got:", fd)
	}

	if s.Invalid != nil {
		t.Fatal("expected invalid prog to be nil due to never being assigned")
	}
}

func BenchmarkNewCollection(b *testing.B) {
	file := fmt.Sprintf("testdata/loader-%s.elf", internal.ClangEndian)
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		b.Fatal(err)
	}

	spec.Maps["array_of_hash_map"].InnerMap = spec.Maps["hash_map"]
	for _, m := range spec.Maps {
		m.Pinning = PinNone
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		coll, err := NewCollection(spec)
		if err != nil {
			b.Fatal(err)
		}
		coll.Close()
	}
}

func BenchmarkNewCollectionManyProgs(b *testing.B) {
	file := fmt.Sprintf("testdata/manyprogs-%s.elf", internal.ClangEndian)
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		coll, err := NewCollection(spec)
		if err != nil {
			b.Fatal(err)
		}
		coll.Close()
	}
}

func ExampleCollectionSpec_Assign() {
	spec := &CollectionSpec{
		Maps: map[string]*MapSpec{
			"map1": {
				Type:       Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
			},
		},
		Programs: map[string]*ProgramSpec{
			"prog1": {
				Type: SocketFilter,
				Instructions: asm.Instructions{
					asm.LoadImm(asm.R0, 0, asm.DWord),
					asm.Return(),
				},
				License: "MIT",
			},
		},
	}

	type maps struct {
		Map *MapSpec `ebpf:"map1"`
	}

	var specs struct {
		maps
		Program *ProgramSpec `ebpf:"prog1"`
	}

	if err := spec.Assign(&specs); err != nil {
		panic(err)
	}

	fmt.Println(specs.Program.Type)
	fmt.Println(specs.Map.Type)

	// Output: SocketFilter
	// Array
}

func ExampleCollectionSpec_LoadAndAssign() {
	spec := &CollectionSpec{
		Maps: map[string]*MapSpec{
			"map1": {
				Type:       Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
			},
		},
		Programs: map[string]*ProgramSpec{
			"prog1": {
				Type: SocketFilter,
				Instructions: asm.Instructions{
					asm.LoadImm(asm.R0, 0, asm.DWord),
					asm.Return(),
				},
				License: "MIT",
			},
		},
	}

	var objs struct {
		Program *Program `ebpf:"prog1"`
		Map     *Map     `ebpf:"map1"`
	}

	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Program.Close()
	defer objs.Map.Close()

	fmt.Println(objs.Program.Type())
	fmt.Println(objs.Map.Type())

	// Output: SocketFilter
	// Array
}
