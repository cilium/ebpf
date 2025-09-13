package ebpf

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/sys"
)

const structOpsValuePrefix = "bpf_struct_ops_"

// structOpsKernTypes groups all kernel-side BTF artefacts that belong to a
// resolved struct_ops.
type structOpsKernTypes struct {
	spec *btf.Spec
	// target kernel struct type (e.g. tcp_congestion_ops).
	typ    *btf.Struct
	typeID btf.TypeID
	// wrapper struct "bpf_struct_ops_<name>" that contains typ.
	valueType *btf.Struct
	// The *btf.Member within valueType that embeds typ.
	dataMember *btf.Member
	// The BTF object ID of the module where the type was found
	// 0 if resolved in vmlinux.
	modBtfObjId uint32
}

// used to holds "environment specific" data
type structOpsSpec struct {
	// programName keeps track of program symbols by attach order.
	programName []string

	// kernFuncOff contains the byte offsets into kernVData where
	// program FDs must be written for function pointer members.
	kernFuncOff []int

	/*
	 * kernVData mirrors the kernel-side representation of the
	 * struct_ops type, including its nested data. For example:
	 *
	 *   struct bpf_struct_ops_tcp_congestion_ops {
	 *       [... kernel internal fields ...]
	 *       struct tcp_congestion_ops data;
	 *   }
	 *
	 * In this case, len(kernVData) == sizeof(struct bpf_struct_ops_tcp_congestion_ops).
	 * copyDataMember() will copy user-supplied data
	 * into kernVData, which is then pushed into the map.
	 */
	kernVData []byte

	// kernTypes describes the BTF types of the target struct_ops
	// object and its nested members, used for resolving offsets
	// and function pointer
	kernTypes *structOpsKernTypes

	// progAttachType maps program names to the sys.AttachType
	// expected by the kernel when attaching each function pointer.
	progAttachType map[string]sys.AttachType

	// progAttachBtfID holds the BTF type ID of the struct_ops
	// target in vmlinux
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

// extractStructOpsMeta retrieves the structOpsMeta value embedded in a
// MapSpec's Contents, following the struct_ops map convention.
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

// findByTypeFromStruct searches for the first member of a struct whose
// resolved BTF type ID matches the given typ.
//
// It resolves the BTF type ID of typ and compares it against each
// member’s TypeID in st.Members. If a match is found, the corresponding
// *btf.Member is returned.
//
// Returns an error if typ cannot be resolved, if any member type
// resolution fails, or if no member with the requested type exists.
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

// findStructByNameWithPrefix resolves a struct_ops "value" type by name,
// after applying the standard prefix convention.
//
// It expects val to be the user-visible struct type (e.g. "bpf_dummy_ops")
// and looks up the kernel-side wrapper name:
//
//	"bpf_dummy_ops" -> "bpf_struct_ops_bpf_dummy_ops"
//
// Returns the matching *btf.Struct, the *btf.Spec it was found in (either the
// base vmlinux spec or a module spec), and the module BTF ID (0 for vmlinux).
// See doFindStructTypeByName for resolution details and error behavior.
func findStructByNameWithPrefix(s *btf.Spec, val *btf.Struct) (*btf.Struct, *btf.Spec, uint32, error) {
	return doFindStructTypeByName(s, structOpsValuePrefix+val.TypeName())
}

// findStructTypeByName resolves the exact BTF struct type that corresponds
// to typ.TypeName() by searching first in vmlinux and then across all loaded
// kernel modules.
//
// Returns the first *btf.Struct that matches the name verbatim, the *btf.Spec
// where it was found, and the module BTF ID (0 if found in vmlinux).
// If no matching struct exists anywhere, btf.ErrNotFound is returned.
func findStructTypeByName(s *btf.Spec, typ *btf.Struct) (*btf.Struct, *btf.Spec, uint32, error) {
	return doFindStructTypeByName(s, typ.TypeName())
}

func findStructTypeByName2(s *btf.Spec, name string) (*btf.Struct, *btf.Spec, uint32, error) {
	return doFindStructTypeByName(s, name)
}

// doFindStructTypeByName looks up a struct type with the exact name in the
// provided base BTF spec, and falls back to scanning all loaded module BTFs
// if it is not present in vmlinux.
//
// Search order and behavior:
//  1. vmlinux (base spec): try AnyTypeByName(name). If it exists and is a
//     *btf.Struct, return it immediately with moduleID=0.
//     - If AnyTypeByName returns a non-notfound error, the error is propagated.
//     - If a type is found but is not a *btf.Struct, we fall back to modules.
//  2. modules: see findStructTypeByNameFromModule.
//
// Returns (*btf.Struct, *btf.Spec, moduleID, nil) on success, or btf.ErrNotFound
// if no matching struct is present in vmlinux or any module.
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

// findStructTypeByNameFromModule scans all loaded kernel modules and tries
// to resolve a struct type with the exact name. The iteration uses the base
// vmlinux spec for string/ID interning as required by btf.Handle.Spec(base).
//
// For the first module where AnyTypeByName(name) returns a *btf.Struct,
// the function returns that struct, the module's *btf.Spec, and its BTF ID.
// If the type is not found in any module, btf.ErrNotFound is returned.
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

// findStructOpsKernTypes discovers all kernel-side BTF artifacts that belong to
// a given struct_ops, identified by the user-visible base struct name
// (e.g., "tcp_congestion_ops").
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

// skipModsAndTypedefs resolves a single layer of BTF indirection/qualification
// for the given type within the provided *btf.Spec.
//
// Behavior:
//   - Uses s.TypeID(typ) and s.TypeByID(id) to canonicalize the type within s.
//   - If the resolved type is a Typedef or C qualifier (Const/Volatile/Restrict),
//     returns its immediate underlying type (one level).
//   - Otherwise returns the resolved type as-is.
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
		// target kernel struct type (e.g. tcp_congestion_ops).
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

// getStructMemberIndexByName returns the index of `member` within struct `s` by
// comparing the member name.
func getStructMemberIndexByName(s *btf.Struct, name string) int {
	for idx, m := range s.Members {
		if m.Name == name {
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
