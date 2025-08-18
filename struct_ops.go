package ebpf

import (
	"errors"
	"fmt"

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
	kernFuncOff []int
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
	return doFindStructTypeByName(s, structOpsValuePrefix+val.TypeName())
}

// findStructTypeByName iterates over *all* BTF types contained in the given Spec and
// returns the first *btf.Struct whose TypeName() exactly matches `name`.
func findStructTypeByName(s *btf.Spec, typ *btf.Struct) (*btf.Struct, *btf.Spec, uint32, error) {
	return doFindStructTypeByName(s, typ.TypeName())
}

// doFindStructTypeByName iterates over *all* BTF types contained in the given Spec and
// returns the first *btf.Struct whose TypeName() exactly matches `name`.
func doFindStructTypeByName(s *btf.Spec, name string) (*btf.Struct, *btf.Spec, uint32, error) {
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
	return findStructTypeByNameFromModule(s, name)
}

// findStructTypeByNameFromModule walks over the BTF info of loaded modules and
// searches for struct `name`.
func findStructTypeByNameFromModule(base *btf.Spec, name string) (*btf.Struct, *btf.Spec, uint32, error) {
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
