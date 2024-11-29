package structops

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
)

type StructOpsField struct {
	Program *ebpf.Program
	Data    []byte
}

func CollectFields(coll *ebpf.Collection, spec *ebpf.MapSpec) (map[string]StructOpsField, error) {
	if spec.Type != ebpf.StructOpsMap {
		return nil, fmt.Errorf("map is not a struct_ops map")
	}

	if len(spec.Contents) == 0 {
		return nil, fmt.Errorf("struct_ops map has no contents")
	}

	specFields := spec.Contents[0].Value.([]ebpf.StructOpsSpecField)
	fields := make(map[string]StructOpsField, len(specFields))
	for _, specField := range specFields {
		if specField.ProgramName != "" {
			prog, ok := coll.Programs[specField.ProgramName]
			if !ok {
				return nil, fmt.Errorf("program %q not found", specField.ProgramName)
			}

			fields[specField.FieldName] = StructOpsField{
				Program: prog,
			}
			continue
		}

		fields[specField.FieldName] = StructOpsField{
			Data: specField.Data,
		}
	}

	return fields, nil
}

func btfSpecFromID(id btf.ID) (*btf.Spec, error) {
	if id == 0 {
		return btf.LoadKernelSpec()
	}

	handle, err := btf.NewHandleFromID(id)
	if err != nil {
		return nil, fmt.Errorf("failed to get btf handle: %w", err)
	}

	var base *btf.Spec
	handleInfo, err := handle.Info()
	if err != nil {
		return nil, fmt.Errorf("failed to get btf handle info: %w", err)
	}
	if handleInfo.IsModule() {
		base, err = btf.LoadKernelSpec()
		if err != nil {
			return nil, fmt.Errorf("failed to load kernel spec: %w", err)
		}
	}

	return handle.Spec(base)
}

func mapValueType(som *ebpf.Map) (valueType, valueDataType *btf.Struct, valueDataOffset uint32, err error) {
	mapInfo, err := som.Info()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get map info: %w", err)
	}

	btfSpec, err := btfSpecFromID(mapInfo.VmlinuxID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get btf spec: %w", err)
	}

	valueTypeIntr, err := btfSpec.TypeByID(mapInfo.VmlinuxValueTypeID)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to get value type: %w", err)
	}

	valueTypeStruct, ok := valueTypeIntr.(*btf.Struct)
	if !ok {
		return nil, nil, 0, fmt.Errorf("value type is not a struct")
	}

	for _, field := range valueTypeStruct.Members {
		if field.Name == "data" {
			valueDataType, ok = field.Type.(*btf.Struct)
			if !ok {
				return nil, nil, 0, fmt.Errorf("value data type is not a struct")
			}
			valueDataOffset = field.Offset.Bytes()
			return valueTypeStruct, valueDataType, valueDataOffset, nil
		}
	}

	return nil, nil, 0, fmt.Errorf("value type has no data field")
}

func SerializeFields(som *ebpf.Map, fields map[string]StructOpsField) ([]byte, error) {
	if som.Type() != ebpf.StructOpsMap {
		return nil, fmt.Errorf("map is not a struct_ops map")
	}

	mapValueType, valueDataType, valueDataOffset, err := mapValueType(som)
	if err != nil {
		return nil, fmt.Errorf("failed to get map value type: %w", err)
	}

	valueSize, err := btf.Sizeof(mapValueType)
	if err != nil {
		return nil, fmt.Errorf("failed to get value size: %w", err)
	}

	serialized := make([]byte, valueSize)

	for _, member := range valueDataType.Members {
		field, found := fields[member.Name]
		if !found {
			continue
		}

		offset := valueDataOffset + member.Offset.Bytes()
		if field.Program != nil {
			internal.NativeEndian.PutUint64(serialized[offset:], uint64(field.Program.FD()))
		} else {
			copy(serialized[offset:], field.Data)
		}
	}

	return serialized, nil
}

type State btf.EnumValue

func DeserializeFields(som *ebpf.Map, value []byte) (refcount uint32, state State, fields map[string]StructOpsField, err error) {
	if som.Type() != ebpf.StructOpsMap {
		return 0, State{}, nil, fmt.Errorf("map is not a struct_ops map")
	}

	mapValueType, valueDataType, valueDataOffset, err := mapValueType(som)
	if err != nil {
		return 0, State{}, nil, fmt.Errorf("failed to get map value type: %w", err)
	}

	valueSize, err := btf.Sizeof(mapValueType)
	if err != nil {
		return 0, State{}, nil, fmt.Errorf("failed to get value size: %w", err)
	}

	if len(value) != valueSize {
		return 0, State{}, nil, fmt.Errorf("value size mismatch, expected %d, got %d", valueSize, len(value))
	}

	for _, member := range mapValueType.Members {
		offset := member.Offset.Bytes()
		// In pre-v6.9 kernels the refcnt and state fields are in the top-level struct.
		// In v6.9 and later kernels they are in a nested struct called "common".
		switch member.Name {
		case "refcnt":
			refcount = internal.NativeEndian.Uint32(value[offset:])
		case "state":
			stateVal := uint64(internal.NativeEndian.Uint32(value[offset:]))
			enum, ok := member.Type.(*btf.Enum)
			if !ok {
				return 0, State{}, nil, fmt.Errorf("state field is not an enum")
			}
			for _, value := range enum.Values {
				if stateVal == value.Value {
					state = State(value)
					break
				}
			}
		case "common":
			commonStruct, ok := member.Type.(*btf.Struct)
			if !ok {
				return 0, State{}, nil, fmt.Errorf("common field is not a struct")
			}

			for _, commonMember := range commonStruct.Members {
				commonOffset := commonMember.Offset.Bytes()
				switch commonMember.Name {
				case "refcnt":
					refcount = internal.NativeEndian.Uint32(value[offset+commonOffset:])
				case "state":
					stateVal := uint64(internal.NativeEndian.Uint32(value[offset+commonOffset:]))
					enum, ok := commonMember.Type.(*btf.Enum)
					if !ok {
						return 0, State{}, nil, fmt.Errorf("state field is not an enum")
					}
					for _, value := range enum.Values {
						if stateVal == value.Value {
							state = State(value)
							break
						}
					}
				}
			}
		}
	}

	fields = make(map[string]StructOpsField, len(valueDataType.Members))
	for _, member := range valueDataType.Members {
		if ptr, ok := member.Type.(*btf.Pointer); ok {
			if _, ok := ptr.Target.(*btf.FuncProto); ok {
				progID := internal.NativeEndian.Uint64(value[valueDataOffset+member.Offset.Bytes():])
				if progID == 0 {
					continue
				}

				prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(progID))
				if err != nil {
					return 0, State{}, nil, fmt.Errorf("failed to load program: %w", err)
				}

				fields[member.Name] = StructOpsField{
					Program: prog,
				}

				continue
			}
		}

		memberSize, err := btf.Sizeof(member.Type)
		if err != nil {
			return 0, State{}, nil, fmt.Errorf("failed to get member size: %w", err)
		}

		offset := int(valueDataOffset + member.Offset.Bytes())
		fields[member.Name] = StructOpsField{
			Data: value[offset : offset+memberSize],
		}
	}

	return refcount, state, fields, nil
}
