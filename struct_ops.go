package ebpf

import (
	"debug/elf"
	"fmt"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/sys"
)

const structOpsLinkSec = ".struct_ops.link"
const structOpsSec = ".struct_ops"

// structOpsKernTypes holds information about kernel types related to struct_ops
type structOpsKernTypes struct {
	// The target kernel struct type
	Type *btf.Struct
	// The BTF type ID of the target kernel struct
	TypeID btf.TypeID
	// The wrapper struct type that contains the target struct
	ValueType *btf.Struct
	// The BTF type ID of the wrapper struct
	ValueTypeID btf.TypeID
	// The member within ValueType that holds the target struct
	DataMember *btf.Member
}

type StructOpsSpec struct {
	ProgramSpecs []*ProgramSpec
	KernFuncOff  []uint32
	/* e.g. struct tcp_congestion_ops in bpf_prog's btf format */
	Data []byte
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
	KernVData []byte
	TypeId    btf.TypeID
	Btf       *btf.Spec
}

func createStructOpsMap(
	spec *btf.Spec,
	varSecInfo *btf.VarSecinfo,
	structType *btf.Struct,
	secIdx elf.SectionIndex,
	sec *elfSection,
) (*MapSpec, error) {
	// Retrieve raw data from the ELF section.
	// This data contains the initial values for the struct_ops map.
	data, err := sec.Data()
	if err != nil {
		return nil, fmt.Errorf("failed to read section data: %w", err)
	}

	// Extract the variable name from the BTF VarSecinfo.
	varVar, ok := varSecInfo.Type.(*btf.Var)
	if !ok {
		return nil, fmt.Errorf("expected Var, got %T", varSecInfo.Type)
	}
	varName := varVar.Name

	// Set map flags based on the section name.
	// For the ".struct_ops.link" section, set the BPF_F_LINK flag.
	flags := uint32(0)
	if sec.Name == structOpsLinkSec {
		flags = sys.BPF_F_LINK
	}

	kernBtf, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("failed to load kernel BTF: %w", err)
	}

	kernStructType, err := kernBtf.AnyTypeByName(structType.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to find kernel BTF type for struct %s: %w", structType.Name, err)
	}

	typ, ok := kernStructType.(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("kernel BTF type %s is not a struct", structType.Name)
	}

	typeID, err := kernBtf.TypeID(kernStructType)
	if err != nil {
		return nil, fmt.Errorf("failed to get BTF type ID for struct %s: %w", structType.Name, err)
	}

	// Prepare the StructOpsSpec, which holds additional information needed for struct_ops maps.
	structOps := &StructOpsSpec{
		ProgramSpecs: make([]*ProgramSpec, len(typ.Members)),
		KernFuncOff:  make([]uint32, len(typ.Members)),
		Data:         make([]byte, typ.Size),
		TypeId:       typeID,
		Btf:          kernBtf.Copy(),
	}

	// Construct the MapSpec for the struct_ops map.
	mapSpec := &MapSpec{
		Name: varName,
		Type: StructOpsMap,
		// Key size is 4 bytes (size of int) for struct_ops maps.
		KeySize: 4,
		// Value size matches the size of the struct.
		ValueSize: typ.Size,
		// Only one entry is needed for struct_ops maps.
		MaxEntries: 1,
		Flags:      flags,
		// BTF Type ID of the map's value type.
		BtfValueTypeId: typeID,
		StructOps:      structOps,
		// Index of the ELF section.
		SecIdx: int32(secIdx),
		// Offset within the section where the map is defined.
		SecOffset: uint64(varSecInfo.Offset),
	}

	// Copy the initial data from the ELF section into the StructOpsSpec.
	// This sets up the initial state of the struct in the map.
	offset := uint64(varSecInfo.Offset)
	size := uint64(structType.Size)
	if offset+size > uint64(len(data)) {
		return nil, fmt.Errorf("variable %s data exceeds section size", varName)
	}
	copy(mapSpec.StructOps.Data, data[offset:offset+size])

	return mapSpec, nil
}

// findStructOpsMapByOffset searches for a struct_ops map in the provided list of MapSpecs.
// This is used to find the appropriate map when processing relocations in ELF sections.
func findStructOpsMapByOffset(maps map[string]*MapSpec, secIdx int32, offset uint64) (*MapSpec, error) {
	for _, mapSpec := range maps {
		if mapSpec.Type != StructOpsMap {
			continue
		}
		// Check if the map's section index matches the target secIdx,
		// and if the offset falls within the map's data range.
		if mapSpec.SecIdx == secIdx && mapSpec.SecOffset <= offset &&
			offset-mapSpec.SecOffset < uint64(mapSpec.ValueSize) {
			return mapSpec, nil
		}
	}

	return nil, fmt.Errorf("no struct_ops map found for secIdx %d and relOffset %d", secIdx, offset)
}

// findStructOpsKernTypes searches for kernel types related to struct_ops by name
func findStructOpsKernTypes(s *btf.Spec, name string) (*structOpsKernTypes, error) {
	if s == nil {
		return nil, fmt.Errorf("BTF spec shouldn't be nil")
	}

	// Find the kernel struct type by name
	kernType, err := s.FindStructTypeByName(name)
	if err != nil {
		return nil, err
	}

	stKernStruct, ok := kernType.(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("kernType %s is not a Struct", kernType.TypeName())
	}

	// Find the wrapper struct that has a specific prefix in its name
	wrapperType, err := s.FindStructByNameWithPrefix(name)
	if err != nil {
		return nil, err
	}

	wrapperStruct, ok := wrapperType.(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("wrapperType %s is not a Struct", wrapperType.TypeName())
	}

	// Find the data member within the wrapper struct that matches the target struct type
	dataMember, err := wrapperStruct.FindByType(s, kernType)
	if err != nil {
		return nil, err
	}

	// Get the type IDs for the target struct and the wrapper struct
	kernTypeID, err := s.TypeID(kernType)
	if err != nil {
		return nil, fmt.Errorf("failed to get type ID of %s: %w", kernType.TypeName(), err)
	}

	wrapperTypeID, err := s.TypeID(wrapperType)
	if err != nil {
		return nil, fmt.Errorf("failed to get type ID of %s: %w", wrapperType.TypeName(), err)
	}

	// Create and return the structOpsKernTypes instance
	return &structOpsKernTypes{
		Type:        stKernStruct,
		TypeID:      kernTypeID,
		ValueType:   wrapperStruct,
		ValueTypeID: wrapperTypeID,
		DataMember:  dataMember,
	}, nil
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
