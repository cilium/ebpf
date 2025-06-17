package ebpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/kallsyms"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/testutils/testmain"
)

func TestMain(m *testing.M) {
	testmain.Run(m)
}

func TestCollectionSpecNotModified(t *testing.T) {
	spec := &CollectionSpec{
		Maps: map[string]*MapSpec{
			"my-map": {
				Type:       Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
			},
			".rodata": {
				Type:       Array,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
				Flags:      0, // Loader sets BPF_F_MMAPABLE.
				Contents:   []MapKV{{uint32(0), uint32(1)}},
			},
		},
		Programs: map[string]*ProgramSpec{
			"test": {
				Type: SocketFilter,
				Instructions: asm.Instructions{
					asm.LoadImm(asm.R1, 0, asm.DWord).WithReference(".rodata"),
					asm.LoadImm(asm.R1, 0, asm.DWord).WithReference("my-map"),
					asm.LoadImm(asm.R0, 0, asm.DWord),
					asm.Return(),
				},
				License: "MIT",
			},
		},
	}

	orig := spec.Copy()
	coll := mustNewCollection(t, spec, nil)
	qt.Assert(t, qt.CmpEquals(orig, spec, csCmpOpts))

	for name := range spec.Maps {
		qt.Assert(t, qt.IsNotNil(coll.Maps[name]))
	}

	for name := range spec.Programs {
		qt.Assert(t, qt.IsNotNil(coll.Programs[name]))
	}
}

func TestCollectionSpecCopy(t *testing.T) {
	ms := &MapSpec{
		Type:       Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}

	cs := &CollectionSpec{
		map[string]*MapSpec{"my-map": ms},
		map[string]*ProgramSpec{
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
		map[string]*VariableSpec{
			"my-var": {
				name:   "my-var",
				offset: 0,
				size:   4,
				m:      ms,
			},
		},
		&btf.Spec{},
		binary.LittleEndian,
	}

	qt.Check(t, qt.IsNil((*CollectionSpec)(nil).Copy()))
	qt.Assert(t, testutils.IsDeepCopy(cs.Copy(), cs))
}

// Load key "0" from a map called "test-map" and return the value.
var loadKeyFromMapProgramSpec = &ProgramSpec{
	Type: SocketFilter,
	Instructions: asm.Instructions{
		// R1 map
		asm.LoadMapPtr(asm.R1, 0).WithReference("test-map"),
		// R2 key
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -4),
		asm.StoreImm(asm.R2, 0, 0, asm.Word),
		// Lookup map[0]
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "error"),
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Word),
		asm.Ja.Label("ret"),
		// Windows doesn't allow directly using R0 result from FnMapLookupElem.
		asm.Mov.Imm(asm.R0, 0).WithSymbol("error"),
		asm.Return().WithSymbol("ret"),
	},
}

func TestCollectionSpecRewriteMaps(t *testing.T) {
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
			"test-prog": loadKeyFromMapProgramSpec.Copy(),
		},
	}

	// Override the map with another one
	newMap := mustNewMap(t, cs.Maps["test-map"], nil)

	err := newMap.Put(uint32(0), uint32(2))
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

	coll := mustNewCollection(t, cs, nil)

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
			"test-prog": loadKeyFromMapProgramSpec.Copy(),
		},
	}

	// Replace the map with another one
	newMap := mustNewMap(t, cs.Maps["test-map"], nil)

	err := newMap.Put(uint32(0), uint32(2))
	if err != nil {
		t.Fatal(err)
	}

	coll := mustNewCollection(t, cs, &CollectionOptions{
		MapReplacements: map[string]*Map{
			"test-map": newMap,
		},
	})

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
	newMap := mustNewMap(t, cs.Maps["test-map"], nil)

	coll, err := newCollection(t, cs, &CollectionOptions{
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
	newMap := mustNewMap(t, &MapSpec{
		Type:       Array,
		KeySize:    4,
		ValueSize:  8, // this is different
		MaxEntries: 1,
	}, nil)

	coll, err := newCollection(t, cs, &CollectionOptions{
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

func TestMapReplacementsDataSections(t *testing.T) {
	// In some circumstances, it can be useful to share data sections between
	// Collections, for example to hold a ready/pause flag or some metrics.
	// Test read-only maps for good measure.
	file := testutils.NativeFile(t, "testdata/loader-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal(err)
	}

	var objs struct {
		Data   *Map `ebpf:".data"`
		ROData *Map `ebpf:".rodata"`
	}

	mustLoadAndAssign(t, spec, &objs, nil)
	defer objs.Data.Close()
	defer objs.ROData.Close()

	mustLoadAndAssign(t, spec, &objs, &CollectionOptions{
		MapReplacements: map[string]*Map{
			".data":   objs.Data,
			".rodata": objs.ROData,
		},
	})
	qt.Assert(t, qt.IsNil(objs.Data.Close()))
	qt.Assert(t, qt.IsNil(objs.ROData.Close()))
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

	mustLoadAndAssign(t, spec, &objs, nil)
	defer objs.Prog.Close()
	defer objs.Map.Close()

	if objs.Prog == nil {
		t.Error("Program is nil")
	}

	if objs.Map == nil {
		t.Error("Map is nil")
	}
}

func TestCollectionSpecAssign(t *testing.T) {
	var specs struct {
		Program  *ProgramSpec  `ebpf:"prog1"`
		Map      *MapSpec      `ebpf:"map1"`
		Variable *VariableSpec `ebpf:"var1"`
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
		Variables: map[string]*VariableSpec{
			"var1": {},
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

func TestNewCollectionFdLeak(t *testing.T) {
	spec := &CollectionSpec{
		Maps: map[string]*MapSpec{
			"map1": {
				Type: Array, KeySize: 4, ValueSize: 4, MaxEntries: 1,
				// 8 byte value will cause m.finalize to fail.
				Contents: []MapKV{{uint32(0), uint64(0)}},
			},
		},
	}

	_, err := newCollection(t, spec, nil)
	qt.Assert(t, qt.IsNotNil(err))
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

func TestCollectionAssign(t *testing.T) {
	var objs struct {
		Program *Program `ebpf:"prog1"`
		Map     *Map     `ebpf:"map1"`
	}

	cs := &CollectionSpec{
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

	coll := mustNewCollection(t, cs, nil)

	qt.Assert(t, qt.IsNil(coll.Assign(&objs)))
	defer objs.Program.Close()
	defer objs.Map.Close()

	// Check that objs has received ownership of map and prog
	qt.Assert(t, qt.IsTrue(objs.Program.FD() >= 0))
	qt.Assert(t, qt.IsTrue(objs.Map.FD() >= 0))

	// Check that the collection has lost ownership
	qt.Assert(t, qt.IsNil(coll.Programs["prog1"]))
	qt.Assert(t, qt.IsNil(coll.Maps["map1"]))
}

func TestCollectionAssignFail(t *testing.T) {
	// `map2` does not exist
	var objs struct {
		Program *Program `ebpf:"prog1"`
		Map     *Map     `ebpf:"map2"`
	}

	cs := &CollectionSpec{
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

	coll := mustNewCollection(t, cs, nil)

	qt.Assert(t, qt.IsNotNil(coll.Assign(&objs)))

	// Check that the collection has retained ownership
	qt.Assert(t, qt.IsNotNil(coll.Programs["prog1"]))
	qt.Assert(t, qt.IsNotNil(coll.Maps["map1"]))
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

	if err := loadAndAssign(t, spec, &s, nil); err == nil {
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
	file := testutils.NativeFile(b, "testdata/loader-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		b.Fatal(err)
	}

	spec.Maps["array_of_hash_map"].InnerMap = spec.Maps["hash_map"]
	for _, m := range spec.Maps {
		m.Pinning = PinNone
	}

	spec = fixupCollectionSpec(spec)

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
	file := testutils.NativeFile(b, "testdata/manyprogs-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		b.Fatal(err)
	}

	spec = fixupCollectionSpec(spec)

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

func BenchmarkLoadCollectionManyProgs(b *testing.B) {
	file, err := os.Open(testutils.NativeFile(b, "testdata/manyprogs-%s.elf"))
	qt.Assert(b, qt.IsNil(err))
	defer file.Close()

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := file.Seek(0, io.SeekStart)
		if err != nil {
			b.Fatal(err)
		}

		_, err = LoadCollectionSpecFromReader(file)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAssignCollectionMany(b *testing.B) {
	var specs []*CollectionSpec
	for i := 0; i < 3; i++ {
		file, err := os.Open(testutils.NativeFile(b, fmt.Sprintf("testdata/kprobe%d-%%s.elf", i+1)))
		qt.Assert(b, qt.IsNil(err))
		defer file.Close()

		spec, err := LoadCollectionSpecFromReader(file)
		if err != nil {
			b.Fatal(err)
		}
		specs = append(specs, spec)
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		b.StopTimer()

		kallsyms.ResetCacheForTest()

		var objs1 struct {
			Program *Program `ebpf:"__scm_send"`
		}
		var objs2 struct {
			Program *Program `ebpf:"fsnotify_remove_first_event"`
		}
		var objs3 struct {
			Program *Program `ebpf:"tcp_connect"`
		}
		objs := []interface{}{&objs1, &objs2, &objs3}

		b.StartTimer()

		// Remove this line to test without optimization
		KallsymsPreLoad([]string{"__scm_send", "fsnotify_remove_first_event", "tcp_connect"})

		for j := 0; j < 3; j++ {
			if err := specs[j].LoadAndAssign(objs[j], nil); err != nil {
				panic(err)
			}
		}
		objs1.Program.Close()
		objs2.Program.Close()
		objs3.Program.Close()
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
}
