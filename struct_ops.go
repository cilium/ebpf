package ebpf

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/sys"
)

const structOpsValuePrefix = "bpf_struct_ops_"

// TODO: Doc
type structOpsProgMetaKey struct{}
type structOpsProgMeta struct {
	attachBtfId btf.TypeID
	attachType  sys.AttachType
	modBtfObjID uint32
}

// structOpsKernTypes holds information about kernel types related to struct_ops
type structOpsKernTypes struct {
	spec *btf.Spec
	// The target kernel struct type
	typ *btf.Struct
	// The BTF type ID of the target kernel struct
	typeID btf.TypeID
	// The wrapper struct type that contains the target struct
	valueType *btf.Struct
	// The member within ValueType that holds the target struct
	dataMember *btf.Member
	// mod_btf
	modBtfObjId uint32
}

// used to holds "environment specific" data
type structOpsSpec struct {
	// attachType -> programSpec
	programName []string
	kernFuncOff []uint32
	/* e.g. struct bpf_struct_ops_tcp_congestion_ops in
	 *      btf_vmlinux's format.
	 * struct bpf_struct_ops_tcp_congestion_ops {
	 *	[... some other kernel fields ...]
	 *	struct tcp_congestion_ops data;
	 * }
	 * kern_vdata-size == sizeof(struct bpf_struct_ops_tcp_congestion_ops)
	 * bpf_map__init_kern_struct_ops() will populate the "kern_vdata"
	 * from "data".
	 */
	kernVData       []byte
	kernTypes       *structOpsKernTypes
	progAttachType  map[string]sys.AttachType
	progAttachBtfID btf.TypeID
}

type structOpsFunc struct {
	member   string // A member name from the user struct
	progName string // A program name which is
}

// structOpsMeta is a placeholder object inserted into MapSpec.Contents
// so that later stages (loader, ELF parser) can recognise this map as
// a struct‑ops map without adding public fields yet.
type structOpsMeta struct {
	funcs []structOpsFunc
	// used for represent a data for the user struct
	// e.g. struct tcp_congestion_ops in bpf_prog's btf format */
	data []byte
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

// findByTypeFromStruct searches the given BTF struct `st` for the *first* member
// whose BTF type **sidentity** equals `typ` (after resolving modifiers).
//
// The comparison is done via TypeID equality inside the same Spec, so a
// typedef chain that ultimately refers to the same concrete type will match.
func findByTypeFromStruct(spec *btf.Spec, st *btf.Struct, typ btf.Type) (*btf.Member, error) {
	typeId, err := spec.TypeID(typ)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve typeId for %s: %w", (typ).TypeName(), err)
	}

	for _, member := range st.Members {
		memberTypeId, err := spec.TypeID(member.Type)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve typeId for %s: %w", member.Name, err)
		}
		if memberTypeId == typeId {
			return &member, nil
		}
	}

	return nil, fmt.Errorf("member of type %s not found in %s", typ.TypeName(), st.Name)
}

// findStructByNameWithPrefix looks up a BTF struct whose name is the given `name`
// prefixed by `structOpsValuePrefix` (“bpf_dummy_ops” → “bpf_struct_ops_bpf_dummy_ops”).
func findStructByNameWithPrefix(s *btf.Spec, val *btf.Struct) (*btf.Struct, *btf.Spec, uint32, error) {
	return doFindStructTypeByName(s, structOpsValuePrefix+val.TypeName(), val)
}

// findStructTypeByName iterates over *all* BTF types contained in the given Spec and
// returns the first *btf.Struct whose TypeName() exactly matches `name`.
func findStructTypeByName(s *btf.Spec, typ *btf.Struct) (*btf.Struct, *btf.Spec, uint32, error) {
	return doFindStructTypeByName(s, typ.TypeName(), typ)
}

// doFindStructTypeByName iterates over *all* BTF types contained in the given Spec and
// returns the first *btf.Struct whose TypeName() exactly matches `name`.
func doFindStructTypeByName(s *btf.Spec, name string, typ *btf.Struct) (*btf.Struct, *btf.Spec, uint32, error) {
	if s == nil {
		return nil, nil, 0, fmt.Errorf("nil BTF: %w", btf.ErrNotFound)
	}

	t, err := s.AnyTypeByName(name)
	if err == nil {
		if typ, ok := t.(*btf.Struct); ok {
			return typ, s, 0, nil
		}
	} else if !errors.Is(err, btf.ErrNotFound) {
		return nil, nil, 0, err
	}
	return findStructTypeByNameFromModule(s, name, typ)
}

// findStructTypeByNameFromModule walks over the BTF info of loaded modules and
// searches for struct `name`.
func findStructTypeByNameFromModule(base *btf.Spec, name string, typ *btf.Struct) (*btf.Struct, *btf.Spec, uint32, error) {
	it := new(btf.HandleIterator)

	for it.Next() {
		defer it.Handle.Close()

		info, err := it.Handle.Info()
		if err != nil {
			return nil, nil, 0, fmt.Errorf("get info for BTF ID %d: %w", it.ID, err)
		}

		if !info.IsModule() {
			continue
		}

		spec, err := it.Handle.Spec(base)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("parse types for module %s: %w", info.Name, err)
		}

		t, err := spec.AnyTypeByName(name)
		if errors.Is(err, btf.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, nil, 0, fmt.Errorf("lookup type in module %s: %w", info.Name, err)
		}

		if typ, ok := t.(*btf.Struct); ok {
			return typ, spec, uint32(it.ID), nil
		}
	}

	return nil, nil, 0, btf.ErrNotFound
}

// findStructOpsKernTypes	discovers all kernel-side BTF artefacts related to a given
//
// *struct_ops* family identified by its **base name** (e.g. "tcp_congestion_ops").
func findStructOpsKernTypes(userStructType *btf.Struct) (*structOpsKernTypes, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("load vmlinux BTF: %w", err)
	}

	// 1. kernel target struct (e.g. tcp_congestion_ops)
	kType, s, modID, err := findStructTypeByName(spec, userStructType)
	if err != nil {
		return nil, fmt.Errorf("struct type: %s %w", userStructType.TypeName(), err)
	}

	// 2. wrapper struct (bpf_struct_ops_<name>)
	wType, _, _, err := findStructByNameWithPrefix(s, userStructType)
	if err != nil {
		return nil, fmt.Errorf("kern struct type for %s %w", userStructType.TypeName(), err)
	}

	// 3. member “data” that embeds the real ops
	dataMem, err := findByTypeFromStruct(s, wType, kType)
	if err != nil {
		return nil, err
	}

	// 4. type-ID of kernel target
	kID, err := s.TypeID(kType)
	if err != nil {
		return nil, fmt.Errorf("type ID of %s: %w", kType.TypeName(), err)
	}

	return &structOpsKernTypes{
		spec:        s,
		typ:         kType,
		typeID:      kID,
		valueType:   wType,
		dataMember:  dataMem,
		modBtfObjId: uint32(modID),
	}, nil
}

// skipModsAndTypedefs returns the **next underlying type** by peeling off a
// single layer of “type wrappers” in BTF:
//
//   - btf.Typedef
//   - btf.Const
//   - btf.Volatile
//   - btf.Restrict
//
// If `typ` is already a concrete type (struct, int, ptr, etc.) it is returned
// unchanged.
func skipModsAndTypedefs(s *btf.Spec, typ btf.Type) (btf.Type, error) {
	typeID, err := s.TypeID(typ)
	if err != nil {
		return nil, fmt.Errorf("failed to find typeid of %s %w", typ.TypeName(), err)
	}

	t, err := s.TypeByID(typeID)
	if err != nil {
		return nil, fmt.Errorf("failed to find type by ID %d: %w", typeID, err)
	}

	switch tt := t.(type) {
	case *btf.Typedef:
		return btf.UnderlyingType(tt.Type), nil
	case *btf.Const:
		return btf.UnderlyingType(tt.Type), nil
	case *btf.Volatile:
		return btf.UnderlyingType(tt.Type), nil
	case *btf.Restrict:
		return btf.UnderlyingType(tt.Type), nil
	default:
		return t, nil
	}
}

// getStructMemberByName searches a BTF struct for a member whose Name equals `name`
// and returns a pointer to that member
func getStructMemberByName(s *btf.Struct, name string) (btf.Member, error) {
	for _, member := range s.Members {
		if member.Name == name {
			return member, nil
		}
	}
	return btf.Member{}, fmt.Errorf("member %s not found in struct %s", name, s.Name)
}

// getStructMemberIndexOf returns the index of `member` within struct `s` by
// comparing the member’s bit-offset.
func getStructMemberIndexOf(s *btf.Struct, member btf.Member) int {
	for idx, m := range s.Members {
		if m.Offset == member.Offset {
			return idx
		}
	}
	return -1
}

// check if the buffer is filled with 0
func isMemoryZero(p []byte) bool {
	for _, b := range p {
		if b != 0 {
			return false
		}
	}
	return true
}

// copyDataMembers processes an individual member of the user-defined struct.
// It determines whether the member is a function pointer or data member,
// and handles it accordingly by setting up program attachments or copying data.
func (sl *structOpsLoader) copyDataMembers(
	kern *structOpsKernTypes,
	structOps *structOpsSpec,
	structOpsMeta *structOpsMeta,
	ms *MapSpec,
	cs *CollectionSpec,
) error {
	kernDataOff := kern.dataMember.Offset / 8
	for idx, member := range kern.typ.Members {
		if err := sl.copyDataMember(
			idx,
			member,
			structOpsMeta.data,
			structOps.kernVData[kernDataOff:],
			kern,
			structOps,
			structOpsMeta,
			ms, cs,
		); err != nil {
			return err
		}
	}

	return nil
}

// copyDataMember processes an individual member of the user-defined struct.
// It determines whether the member is a function pointer or data member,
// and handles it accordingly by setting up program attachments or copying data.
func (sl *structOpsLoader) copyDataMember(
	idx int,
	member btf.Member,
	data, kernData []byte,
	kern *structOpsKernTypes,
	structOps *structOpsSpec,
	structOpsMeta *structOpsMeta,
	ms *MapSpec,
	cs *CollectionSpec,
) error {
	memberName := member.Name
	memberOff := member.Offset / 8
	memberData := data[memberOff:]

	memberSize, err := btf.Sizeof(member.Type)
	if err != nil {
		return fmt.Errorf("failed to resolve the size of member %s: %w", memberName, err)
	}

	kernMember, err := getStructMemberByName(kern.typ, memberName)
	if err != nil {
		if isMemoryZero(memberData[:memberSize]) {
			// Skip if member doesn't exist in kernel BTF and data is zero
			return nil
		}
		return fmt.Errorf("member %s not found in kernel BTF and data is not zero", memberName)
	}

	kernMemberIdx := getStructMemberIndexOf(kern.typ, kernMember)
	if member.BitfieldSize > 0 || kernMember.BitfieldSize > 0 {
		return fmt.Errorf("bitfield %s is not supported", memberName)
	}

	kernMemberOff := kernMember.Offset / 8
	kernMemberData := kernData[kernMemberOff:]
	memberType, err := skipModsAndTypedefs(kern.spec, member.Type)
	if err != nil {
		return fmt.Errorf("user: failed to skip typedefs for %s: %w", memberName, err)
	}

	kernMemberType, err := skipModsAndTypedefs(kern.spec, kernMember.Type)
	if err != nil {
		return fmt.Errorf("kern: failed to skip typedefs for %s: %w", kernMember.Name, err)
	}

	if _, ok := memberType.(*btf.Pointer); ok {
		var fnName string

		for _, fn := range structOpsMeta.funcs {
			if fn.member == memberName {
				fnName = fn.progName
				break
			}

		}
		if fnName == "" {
			// skip if the member is not specified in the MapSpec
			return nil
		}

		ps, ok := cs.Programs[fnName]
		if !ok {
			return fmt.Errorf("Program %s is not found in CollectionSpec", fnName)
		}
		if ps.Type != StructOps {
			return fmt.Errorf("program %s is not a valid StructOps program", fnName)
		}

		attachType := sys.AttachType(kernMemberIdx)
		if int(attachType) > len(kern.typ.Members) {
			return fmt.Errorf("program %s: unexpected attach type %d", ps.Name, attachType)
		}

		kernFuncOff := kern.dataMember.Offset/8 + kern.typ.Members[kernMemberIdx].Offset/8
		structOps.kernFuncOff[idx] = uint32(kernFuncOff)
		structOps.progAttachType[ps.Name] = attachType
		sl.stOpsProgsToMap[ps.Name] = ms.Name

		ps.Instructions[0].Metadata.Set(structOpsProgMetaKey{}, &structOpsProgMeta{
			attachBtfId: kern.typeID,
			attachType:  attachType,
			modBtfObjID: kern.modBtfObjId,
		})
	}

	// Handle data member. copy data members from the user-defined struct to the kernel data buffer.
	// It ensures that the sizes match between user and kernel types before copying the data.
	kernMemberSize, err := btf.Sizeof(kernMemberType)
	if err != nil || memberSize != kernMemberSize {
		return fmt.Errorf("size mismatch for member %s: %d != %d (kernel)", memberName, memberSize, kernMemberSize)
	}
	copy(kernMemberData[:memberSize], memberData[:memberSize])

	return nil
}

// TODO: All following items should be moved into collectionLoader

type structOpsLoader struct {
	// map name -> structOpsSpec
	stOpsSpecs map[string]*structOpsSpec
	// structOps program name -> structOpsMap name
	stOpsProgsToMap map[string]string
}

func newStructOpsLoader() *structOpsLoader {
	return &structOpsLoader{
		stOpsSpecs:      make(map[string]*structOpsSpec),
		stOpsProgsToMap: make(map[string]string),
	}
}

// TODO: should be RENAMED AND MOVED!!!!

// preLoad collects typed metadata for struct_ops maps from the CollectionSpec.
// It does not modify specs nor create kernel objects. Value population happens in a follow-up PR.
func (sl *structOpsLoader) preLoad(cs *CollectionSpec) error {
	for _, ms := range cs.Maps {
		if ms.Type != StructOpsMap {
			continue
		}

		userSt := ms.Value
		if userSt == nil {
			return fmt.Errorf("user struct type should be specified as Value")
		}

		userStructType, ok := ms.Value.(*btf.Struct)
		if !ok {
			return fmt.Errorf("user struct type should be a Struct")
		}

		kernTypes, err := findStructOpsKernTypes(userStructType)
		if err != nil {
			return fmt.Errorf("find kern_type: %w", err)
		}
		ms.Value = kernTypes.typ

		structOps := &structOpsSpec{
			make([]string, len(kernTypes.typ.Members)),
			make([]uint32, len(kernTypes.typ.Members)),
			make([]byte, kernTypes.valueType.Size),
			kernTypes,
			make(map[string]sys.AttachType),
			kernTypes.typeID,
		}
		sl.stOpsSpecs[ms.Name] = structOps

		structOpsMeta, err := extractStructOpsMeta(ms.Contents)
		if err != nil {
			return err
		}

		// process struct members
		if err := sl.copyDataMembers(
			kernTypes,
			structOps,
			structOpsMeta,
			ms, cs,
		); err != nil {
			return err
		}
	}

	return nil
}

// TODO: should be RENAMED AND MOVED!!!!

// onProgramLoaded is called right after a Program has been successfully
// loaded by collectionLoader.loadProgram().  If the program belongs to a
// struct_ops map it records the program for later FD-injection.
func (sl *structOpsLoader) onProgramLoaded(
	p *Program,
	progSpec *ProgramSpec,
) error {

	mapName, ok := sl.stOpsProgsToMap[p.name]
	if !ok {
		return nil
	}

	structOps, ok := sl.stOpsSpecs[mapName]
	if !ok {
		// this is unlikely to happen.
		return fmt.Errorf("program %s has been loaded but not associated", p.name)
	}

	attachType := structOps.progAttachType[p.name]
	if int(attachType) > len(structOps.kernTypes.typ.Members) {
		return fmt.Errorf("program %s: unexpected attach type %d", p.name, attachType)
	}
	structOps.programName[attachType] = progSpec.Name

	return nil
}

// TODO: should be RENAMED AND MOVED!!!!

// postLoad runs after all maps and programs have been loaded.
// It writes program FDs into struct_ops.KernVData and updates the map entry.
func (sl *structOpsLoader) postLoad(maps map[string]*Map, progs map[string]*Program) error {
	for mapName, m := range maps {
		if m.Type() != StructOpsMap {
			continue
		}

		structOps, ok := sl.stOpsSpecs[mapName]
		if !ok {
			return fmt.Errorf("struct_ops Map: %s is not initialized", mapName)
		}

		for idx, progName := range structOps.programName {
			if progName == "" {
				continue
			}

			prog, ok := progs[progName]
			if !ok {
				return fmt.Errorf("program %s should be loaded", progName)
			}
			defer prog.Close()

			off := structOps.kernFuncOff[idx]
			ptr := unsafe.Pointer(&structOps.kernVData[0])
			*(*uint64)(unsafe.Pointer(uintptr(ptr) + uintptr(off))) = uint64(prog.FD())
		}

		m, ok := maps[mapName]
		if !ok {
			return fmt.Errorf("map %s should be loaded", mapName)
		}

		if err := m.Put(uint32(0), structOps.kernVData); err != nil {
			return err
		}
	}
	return nil
}
