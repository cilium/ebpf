package ebpf

import (
	"github.com/cilium/ebpf/internal/sys"
)

// An arbitrary value used to distinguish unsupported from supported
// types on Windows.
const windowsUnsupportedTypeStart = 1_000_000

//go:generate go run github.com/cilium/ebpf/internal/cmd/genstrings types_string -type=MapType,PinType

// MapType indicates the type map structure
// that will be initialized in the kernel.
type MapType uint32

// hasPerCPUValue returns true if the Map stores a value per CPU.
func (mt MapType) hasPerCPUValue() bool {
	return mt == PerCPUHash || mt == PerCPUArray || mt == LRUCPUHash || mt == PerCPUCGroupStorage
}

// canStoreMapOrProgram returns true if the Map stores references to another Map
// or Program.
func (mt MapType) canStoreMapOrProgram() bool {
	return mt.canStoreMap() || mt.canStoreProgram()
}

// canStoreMap returns true if the map type accepts a map fd
// for update and returns a map id for lookup.
func (mt MapType) canStoreMap() bool {
	return mt == ArrayOfMaps || mt == HashOfMaps
}

// canStoreProgram returns true if the map type accepts a program fd
// for update and returns a program id for lookup.
func (mt MapType) canStoreProgram() bool {
	return mt == ProgramArray
}

//go:generate go run github.com/cilium/ebpf/internal/cmd/genstrings types_program_string -type ProgramType

// ProgramType of the eBPF program
type ProgramType uint32

//go:generate go run github.com/cilium/ebpf/internal/cmd/genstrings types_attach_string -type AttachType -trimprefix Attach

// AttachType of the eBPF program, needed to differentiate allowed context accesses in
// some newer program types like CGroupSockAddr. Should be set to AttachNone if not required.
// Will cause invalid argument (EINVAL) at program load time if set incorrectly.
type AttachType uint32

// AttachFlags of the eBPF program used in BPF_PROG_ATTACH command
type AttachFlags uint32

// PinType determines whether a map is pinned into a BPFFS.
type PinType uint32

// Valid pin types.
//
// Mirrors enum libbpf_pin_type.
const (
	PinNone PinType = iota
	// Pin an object by using its name as the filename.
	PinByName
)

// LoadPinOptions control how a pinned object is loaded.
type LoadPinOptions struct {
	// Request a read-only or write-only object. The default is a read-write
	// object. Only one of the flags may be set.
	ReadOnly  bool
	WriteOnly bool

	// Raw flags for the syscall. Other fields of this struct take precedence.
	Flags uint32
}

// Marshal returns a value suitable for BPF_OBJ_GET syscall file_flags parameter.
func (lpo *LoadPinOptions) Marshal() uint32 {
	if lpo == nil {
		return 0
	}

	flags := lpo.Flags
	if lpo.ReadOnly {
		flags |= sys.BPF_F_RDONLY
	}
	if lpo.WriteOnly {
		flags |= sys.BPF_F_WRONLY
	}
	return flags
}

// BatchOptions batch map operations options
//
// Mirrors libbpf struct bpf_map_batch_opts
// Currently BPF_F_FLAG is the only supported
// flag (for ElemFlags).
type BatchOptions struct {
	ElemFlags uint64
	Flags     uint64
}

// LogLevel controls the verbosity of the kernel's eBPF program verifier.
// These constants can be used for the ProgramOptions.LogLevel field.
type LogLevel = sys.LogLevel

const (
	// Print verifier state at branch points.
	LogLevelBranch = sys.BPF_LOG_LEVEL1

	// Print verifier state for every instruction.
	// Available since Linux v5.2.
	LogLevelInstruction = sys.BPF_LOG_LEVEL2

	// Print verifier errors and stats at the end of the verification process.
	// Available since Linux v5.2.
	LogLevelStats = sys.BPF_LOG_STATS
)
