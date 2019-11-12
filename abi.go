package ebpf

import "github.com/pkg/errors"

// MapABI describes a Map.
type MapABI struct {
	Type       MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	InnerMap   *MapABI
}

func newMapABIFromSpec(spec *MapSpec) *MapABI {
	var inner *MapABI
	if spec.InnerMap != nil {
		inner = newMapABIFromSpec(spec.InnerMap)
	}

	return &MapABI{
		spec.Type,
		spec.KeySize,
		spec.ValueSize,
		spec.MaxEntries,
		inner,
	}
}

func newMapABIFromFd(fd *bpfFD) (*MapABI, error) {
	info, err := bpfGetMapInfoByFD(fd)
	if err != nil {
		return nil, err
	}

	mapType := MapType(info.mapType)
	if mapType == ArrayOfMaps || mapType == HashOfMaps {
		return nil, errors.New("can't get map info for nested maps")
	}

	return &MapABI{
		mapType,
		info.keySize,
		info.valueSize,
		info.maxEntries,
		nil,
	}, nil
}

// ProgramABI describes a Program.
type ProgramABI struct {
	Type ProgramType
}

func newProgramABIFromSpec(spec *ProgramSpec) *ProgramABI {
	return &ProgramABI{
		spec.Type,
	}
}

func newProgramABIFromFd(fd *bpfFD) (*ProgramABI, error) {
	info, err := bpfGetProgInfoByFD(fd)
	if err != nil {
		return nil, err
	}

	return newProgramABIFromInfo(info), nil
}

func newProgramABIFromInfo(info *bpfProgInfo) *ProgramABI {
	return &ProgramABI{
		Type: ProgramType(info.progType),
	}
}
