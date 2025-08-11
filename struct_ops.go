package ebpf

import "fmt"

// structOpsMeta is a placeholder object inserted into MapSpec.Contents
// so that later stages (loader, ELF parser) can recognise this map as
// a struct‑ops map without adding public fields yet.
type structOpsMeta struct {
	userTypeName string
	kernTypeName string
}

// extractStructOpsMeta returns the *structops.Meta embedded in a MapSpec’s Contents
// according to the struct-ops convention:
//
//	contents[0].Key   == uint32(0)
//	contents[0].Value == *structopsMeta
func extractStructOpsMeta(contents []MapKV) (*structOpsMeta, error) {
	if len(contents) == 0 {
		return nil, fmt.Errorf("struct_ops: missing meta at Contents[0]")
	}

	k, ok := contents[0].Key.(uint32)
	if !ok || k != 0 {
		return nil, fmt.Errorf("struct_ops: meta key must be 0")
	}

	meta, ok := contents[0].Value.(structOpsMeta)
	if !ok {
		return nil, fmt.Errorf("struct_ops: meta value must be structOpsMeta")
	}

	return &meta, nil
}

type structOpsLoader struct {
	metas       map[string]*structOpsMeta
	specCopy    map[string]*MapSpec
	progsByName map[string]*Program
}

func newStructOpsLoader() *structOpsLoader {
	return &structOpsLoader{
		metas:       make(map[string]*structOpsMeta),
		specCopy:    make(map[string]*MapSpec),
		progsByName: make(map[string]*Program),
	}
}

// preLoad collects typed metadata for struct_ops maps from the CollectionSpec.
// It does not modify specs nor create kernel objects. Value population happens in a follow-up PR.
func (sl *structOpsLoader) preLoad(cs *CollectionSpec) error {
	return nil
}

// onProgramLoaded is called right after a Program has been successfully
// loaded by collectionLoader.loadProgram().  If the program belongs to a
// struct_ops map it records the program for later FD injection.
func (sl *structOpsLoader) onProgramLoaded(p *Program, ps *ProgramSpec, cs *CollectionSpec) error {
	if ps.Type != StructOps {
		return nil
	}
	sl.progsByName[ps.Name] = p
	return nil
}

// onProgramLoaded is called right after a Program has been successfully
// loaded by collectionLoader.loadProgram().  If the program belongs to a
// struct_ops map it records the program for later FD injection.
func (sl *structOpsLoader) postLoad(loadedMaps map[string]*Map) error {
	return nil
}
