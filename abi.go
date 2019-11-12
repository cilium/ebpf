package ebpf

// MapABI are the attributes of a Map which are available across all supported kernels.
type MapABI struct {
	Type       MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

func newMapABIFromSpec(spec *MapSpec) *MapABI {
	return &MapABI{
		spec.Type,
		spec.KeySize,
		spec.ValueSize,
		spec.MaxEntries,
		spec.Flags,
	}
}

func newMapABIFromFd(fd *bpfFD) (*MapABI, error) {
	info, err := bpfGetMapInfoByFD(fd)
	if err != nil {
		return nil, err
	}

	return &MapABI{
		MapType(info.mapType),
		info.keySize,
		info.valueSize,
		info.maxEntries,
		info.flags,
	}, nil
}

// Equal returns true if two ABIs have the same values.
func (abi *MapABI) Equal(other *MapABI) bool {
	switch {
	case abi.Type != other.Type:
		return false
	case abi.KeySize != other.KeySize:
		return false
	case abi.ValueSize != other.ValueSize:
		return false
	case abi.MaxEntries != other.MaxEntries:
		return false
	case abi.Flags != other.Flags:
		return false
	default:
		return true
	}
}

// ProgramABI are the attributes of a Program which are available across all supported kernels.
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

// Equal returns true if two ABIs have the same values.
func (abi *ProgramABI) Equal(other *ProgramABI) bool {
	switch {
	case abi.Type != other.Type:
		return false
	default:
		return true
	}
}
