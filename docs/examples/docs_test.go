package examples

import (
	"fmt"

	"github.com/cilium/ebpf"
)

func DocLoadCollectionSpec() {
	// Parse an ELF into a CollectionSpec.
	// bpf_prog.o is the result of compiling BPF C code.
	spec, err := ebpf.LoadCollectionSpec("bpf_prog.o")
	if err != nil {
		panic(err)
	}

	// Look up the MapSpec and ProgramSpec in the CollectionSpec.
	m := spec.Maps["my_map"]
	p := spec.Programs["my_prog"]
	// Note: We've omitted nil checks for brevity, take a look at
	// LoadAndAssign for an automated way of checking for maps/programs.

	// Inspect the map and program type.
	fmt.Println(m.Type, p.Type)

	// Print the map's key and value BTF types.
	fmt.Println(m.Key, m.Value)

	// Print the program's instructions in a human-readable form,
	// similar to llvm-objdump -S.
	fmt.Println(p.Instructions)
}

func DocNewCollection() {
	spec, err := ebpf.LoadCollectionSpec("bpf_prog.o")
	if err != nil {
		panic(err)
	}

	// Instantiate a Collection from a CollectionSpec.
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}
	// Close the Collection before the enclosing function returns.
	defer coll.Close()

	// Obtain a reference to 'my_map'.
	m := coll.Maps["my_map"]

	// Set map key '1' to value '2'.
	if err := m.Put(uint32(1), uint64(2)); err != nil {
		panic(err)
	}
}

// DocLoadAndAssignObjs {
type myObjs struct {
	MyMap  *ebpf.Map     `ebpf:"my_map"`
	MyProg *ebpf.Program `ebpf:"my_prog"`
}

func (objs *myObjs) Close() error {
	if err := objs.MyMap.Close(); err != nil {
		return err
	}
	if err := objs.MyProg.Close(); err != nil {
		return err
	}
	return nil
}

// }

func DocLoadAndAssign() {
	spec, err := ebpf.LoadCollectionSpec("bpf_prog.o")
	if err != nil {
		panic(err)
	}

	// Insert only the resources specified in 'obj' into the kernel and assign
	// them to their respective fields. If any requested resources are not found
	// in the ELF, this will fail. Any errors encountered while loading Maps or
	// Programs will also be returned here.
	var objs myObjs
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Close()

	// Interact with MyMap through the custom struct.
	if err := objs.MyMap.Put(uint32(1), uint64(2)); err != nil {
		panic(err)
	}
}

func DocBTFTypeByName() {
	spec, err := ebpf.LoadCollectionSpec("bpf_prog.o")
	if err != nil {
		panic(err)
	}

	// Look up the __64 type declared in linux/bpf.h.
	t, err := spec.Types.AnyTypeByName("__u64")
	if err != nil {
		panic(err)
	}
	fmt.Println(t)
}
