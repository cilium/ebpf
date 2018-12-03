package ebpf

//go:generate stringer -output types_string.go -type=MapType,ProgType

// MapType indicates the type map structure
// that will be initialized in the kernel.
type MapType uint32

// All the various map types that can be created
const (
	UnspecifiedMap MapType = iota
	// Hash is a hash map
	Hash
	// Array is an array map
	Array
	// ProgramArray - A program array map is a special kind of array map whose map
	// values contain only file descriptors referring to other eBPF
	// programs.  Thus, both the key_size and value_size must be
	// exactly four bytes.  This map is used in conjunction with the
	// TailCall helper.
	ProgramArray
	// PerfEventArray - A perf event array is used in conjunction with PerfEventRead
	// and PerfEventOutput calls, to read the raw bpf_perf_data from the registers.
	PerfEventArray
	// PerCPUHash - This data structure is useful for people who have high performance
	// network needs and can reconcile adds at the end of some cycle, so that
	// hashes can be lock free without the use of XAdd, which can be costly.
	PerCPUHash
	// PerCPUArray - This data structure is useful for people who have high performance
	// network needs and can reconcile adds at the end of some cycle, so that
	// hashes can be lock free without the use of XAdd, which can be costly.
	// Each CPU gets a copy of this hash, the contents of all of which can be reconciled
	// later.
	PerCPUArray
	// StackTrace - This holds whole user and kernel stack traces, it can be retrieved with
	// GetStackID
	StackTrace
	// CGroupArray - This is a very niche structure used to help SKBInCGroup determine
	// if an skb is from a socket belonging to a specific cgroup
	CGroupArray
	// LRUHash - This allows you to create a small hash structure that will purge the
	// least recently used items rather than thow an error when you run out of memory
	LRUHash
	// LRUCPUHash - This is NOT like PerCPUHash, this structure is shared among the CPUs,
	// it has more to do with including the CPU id with the LRU calculation so that if a
	// particular CPU is using a value over-and-over again, then it will be saved, but if
	// a value is being retrieved a lot but sparsely across CPUs it is not as important, basically
	// giving weight to CPU locality over overall usage.
	LRUCPUHash
	// LPMTrie - This is an implementation of Longest-Prefix-Match Trie structure. It is useful,
	// for storing things like IP addresses which can be bit masked allowing for keys of differing
	// values to refer to the same reference based on their masks. See wikipedia for more details.
	LPMTrie
	// ArrayOfMaps - Each item in the array is another map. The inner map mustn't be a map of maps
	// itself.
	ArrayOfMaps
	// HashOfMaps - Each item in the hash map is another map. The inner map mustn't be a map of maps
	// itself.
	HashOfMaps
)

// hasPerCPUValue returns true if the Map stores a value per CPU.
func (mt MapType) hasPerCPUValue() bool {
	if mt == PerCPUHash || mt == PerCPUArray {
		return true
	}
	return false
}

const (
	_MapCreate = iota
	_MapLookupElem
	_MapUpdateElem
	_MapDeleteElem
	_MapGetNextKey
	_ProgLoad
	_ObjPin
	_ObjGet
	_ProgAttach
	_ProgDetach
	_ProgTestRun
	_ProgGetNextID
	_MapGetNextID
	_ProgGetFDByID
	_MapGetFDByID
	_ObjGetInfoByFD
)

const (
	_Any = iota
	_NoExist
	_Exist
)

// All flags used by eBPF helper functions
const (
	// RecomputeCSUM SKBStoreBytes flags
	RecomputeCSUM = uint64(1)
	// FInvalidateHash SKBStoreBytes flags
	FInvalidateHash = uint64(1 << 1)

	// FHdrFieldMask CSUMReplaceL4 and CSUMReplaceL3 flags.
	// First 4 bits are for passing the header field size.
	FHdrFieldMask = uint64(0xF)

	// FPseudoHdr CSUMReplaceL4 flags
	FPseudoHdr = uint64(1 << 4)
	// FMarkMangled0 CSUMReplaceL4 flags
	FMarkMangled0 = uint64(1 << 5)
	// FMakrEnforce CSUMReplaceL4 flags
	FMakrEnforce = uint64(1 << 6)

	// FIngress CloneRedirect and Redirect flags
	FIngress = uint64(1)

	// FTunInfoIPV6 SKBSetTunnelKey and SKBGetTunnelKey flags
	FTunInfoIPV6 = uint(1)

	// FSkipFieldMask GetStackID flags
	FSkipFieldMask = uint64(0xff)
	// FUserStack GetStackID flags
	FUserStack = uint64(1 << 8)
	// FFastStackCMP GetStackID flags
	FFastStackCMP = uint64(1 << 9)
	// FReuseStackID GetStackID flags
	FReuseStackID = uint64(1 << 10)

	// FZeroCSUMTx SKBSetTunnelKey flag
	FZeroCSUMTX = uint64(1 << 1)
	// FZeroCSUMTx SKBSetTunnelKey flag
	FDontFragment = uint64(1 << 2)

	// FindIndexMask PerfEventOutput and PerfEventRead flags.
	FIndexMask = uint64(0xffffffff)
	// FCurrentCPU PerfEventOutput and PerfEventRead flags.
	FCurrentCPU = FIndexMask

	// FCtxLenMask PerfEventOutput for SKBuff input context.
	FCtxLenMask = uint64(0xfffff << 32)

	// AdjRoomNet Mode for SKBAdjustRoom helper.
	AdjRoomNet = 0
)

// ProgType of the eBPF program
type ProgType uint32

// eBPF program types
const (
	// Unrecognized program type
	Unrecognized ProgType = iota
	// SocketFilter socket or seccomp filter
	SocketFilter
	// Kprobe program
	Kprobe
	// SchedCLS traffic control shaper
	SchedCLS
	// SchedACT routing control shaper
	SchedACT
	// TracePoint program
	TracePoint
	// XDP program
	XDP
	// PerfEvent program
	PerfEvent
	// CGroupSKB program
	CGroupSKB
	// CGroupSock program
	CGroupSock
	// LWTIn program
	LWTIn
	// LWTOut program
	LWTOut
	// LWTXmit program
	LWTXmit
	// SockOps program
	SockOps
)
