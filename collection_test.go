package ebpf

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

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
					asm.LoadImm(asm.R1, 0, asm.DWord),
					asm.LoadImm(asm.R0, 0, asm.DWord),
					asm.Return(),
				},
				License: "MIT",
			},
		},
	}

	cs.Programs["test"].Instructions[0].Reference = "my-map"

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
}

func TestCollectionSpecRewriteMaps(t *testing.T) {
	insns := asm.Instructions{
		// R1 map
		asm.LoadMapPtr(asm.R1, 0),
		// R2 key
		asm.Mov.Reg(asm.R2, asm.R10),
		asm.Add.Imm(asm.R2, -4),
		asm.StoreImm(asm.R2, 0, 0, asm.Word),
		// Lookup map[0]
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "ret"),
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Word),
		asm.Return().Sym("ret"),
	}
	insns[0].Reference = "test-map"

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

	ret, _, err := coll.Programs["test-prog"].Test(make([]byte, 14))
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 2 {
		t.Fatal("new / override map not used")
	}
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

	coll, err := NewCollection(cs)
	if err != nil {
		t.Fatal(err)
	}
	defer coll.Close()

	var objs struct {
		Program *Program `ebpf:"prog1"`
		Map     *Map     `ebpf:"map1"`
	}

	if err := coll.Assign(&objs); err != nil {
		t.Fatal("Can't Assign objects:", err)
	}
	objs.Program.Close()
	objs.Map.Close()

	if coll.Programs["prog1"] != nil {
		t.Fatal("Assign doesn't detach Program")
	}

	if coll.Maps["map1"] != nil {
		t.Fatal("Assign doesn't detach Map")
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

	var specs struct {
		Program *ProgramSpec `ebpf:"prog1"`
		Map     *MapSpec     `ebpf:"map1"`
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

	fmt.Println(objs.Program.Type())
	fmt.Println(objs.Map.Type())

	// Output: SocketFilter
	// Array
}

func ExampleCollection_Assign() {
	coll, err := NewCollection(&CollectionSpec{
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
	})
	if err != nil {
		panic(err)
	}

	var objs struct {
		Program *Program `ebpf:"prog1"`
		Map     *Map     `ebpf:"map1"`
	}

	if err := coll.Assign(&objs); err != nil {
		panic(err)
	}

	fmt.Println(objs.Program.Type())
	fmt.Println(objs.Map.Type())

	// Output: SocketFilter
	// Array
}
