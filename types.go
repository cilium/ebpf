package ebpf

import (
	"bytes"
	"fmt"
	"strings"
)

//go:generate stringer -output types_string.go -type=MapType,ProgType

// MapType indicates the type map structure
// that will be initialized in the kernel.
type MapType uint32

// All the various map types that can be created
const (
	// Hash is a hash map
	Hash MapType = 1 + iota
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

// Limits and constants for the the eBPF runtime
const (
	// StackSize is the total size of the stack allocated for BPF programs
	StackSize = 512
	// InstructionSize is the size of the BPF instructions
	InstructionSize = 8
	// LogBufSize is the size of the log buffer for debugging issues
	LogBufSize = 65536
)

// Class masks for eBPF operators
// opcode structure:
// msb      lsb
// +---+--+---+
// |mde|sz|CLS|
// +---+--+---+
const (
	// ClassCode is the bitmask for the class bitfield
	ClassCode = 0x07
	// LdClass load memory
	LdClass = 0x00
	// LdXClass load memory from constant
	LdXClass = 0x01
	// StClass load registry from memory
	StClass = 0x02
	// StXClass load registry from constan
	StXClass = 0x03
	// ALUClass arithmetic operators
	ALUClass = 0x04
	// JmpClass jump operators
	JmpClass = 0x05
	// RetClass return operator
	RetClass = 0x06
	// MiscClass exit, et al operators
	MiscClass = 0x07
	// ALU64Class arithmetic in 64 bit mode; eBPF only
	ALU64Class = 0x07
)

// Size masks for eBPF operators
// opcode structure:
// msb      lsb
// +---+--+---+
// |mde|SZ|cls|
// +---+--+---+
const (
	// SizeCode is the bitmask for the size bitfield
	SizeCode = 0x18
	// DWSize - double word; 64 bits; eBPF only
	DWSize = 0x18
	// WSize - word; 32 bits
	WSize = 0x00
	// HSize - half-word; 16 bits
	HSize = 0x08
	// BSize - byte; 8 bits
	BSize = 0x10
)

// Mode masks for eBPF operators
// opcode structure:
// msb      lsb
// +---+--+---+
// |MDE|sz|cls|
// +---+--+---+
const (
	// ModeCode is the bitmask for the mode bitfield
	ModeCode = 0xe0
	// ImmMode - immediate value
	ImmMode = 0x00
	// AbsMode - immediate value + offset
	AbsMode = 0x20
	// IndMode - indirect (imm+src)
	IndMode = 0x40
	// MemMode - load from memory
	MemMode = 0x60
	// LenMode - ??
	LenMode = 0x80
	// MshMode - ??
	MshMode = 0xa0
	// XAddMode - add atomically across processors; eBPF only.
	XAddMode = 0xc0
)

// alu/alu64/jmp opcode structure:
// msb      lsb
// +----+-+---+
// |OP  |s|cls|
// +----+-+---+
// If the s bit is zero, then the source operand is imm,
// If s is one, then the source operand is src.
const (
	// OpCode is the bitmask for ALU operator bitfield
	OpCode = 0xf0
	// AddOp - addition
	AddOp = 0x00
	// SubOp - subtraction
	SubOp = 0x10
	// MulOp - multiplication
	MulOp = 0x20
	// DivOp - division
	DivOp = 0x30
	// OrOp - bitwise or
	OrOp = 0x40
	// AndOp - bitwise and
	AndOp = 0x50
	// LShOp - bitwise shift left
	LShOp = 0x60
	// RShOp - bitwise shift right
	RShOp = 0x70
	// NegOp - sign/unsign signing bit
	NegOp = 0x80
	// ModOp - modulo
	ModOp = 0x90
	// XOrOp - bitwise xor
	XOrOp = 0xa0
	// MovOp - move value from one place to another; eBPF only.
	MovOp = 0xb0
	// ArShOp - arithmatic shift; eBPF only.
	ArShOp = 0xc0

	// EndFlag endian flag mode, eBPF only
	EndFlag = 0xd0
	// ToLeFlag toLE instruction, eBPF only
	ToLeFlag = 0x00
	// ToBeFlag toBE instruction, eBPF only
	ToBeFlag = 0x08
	// FromLeFlag fromLE instruction, eBPF only
	FromLeFlag = 0x00
	// FromBeFlag fromBE instruction, eBPF only
	FromBeFlag = 0x08
)

// Branch instruction opcode masks
const (
	// JaOp to address
	JaOp = 0x00
	// JEqOp to address if r == imm
	JEqOp = 0x10
	// JGTOp to address if r > imm
	JGTOp = 0x20
	// JGEOp to address if r >= imm
	JGEOp = 0x30
	// JSETOp to address if signed r == signed imm
	JSETOp = 0x40
	// JNEOp to address if r != imm, eBPF only
	JNEOp = 0x50
	// JSGTOp to address if signed r > signed imm, eBPF only
	JSGTOp = 0x60
	// JSGEOp to address if signed r >= signed imm, eBPF only
	JSGEOp = 0x70
	// CallOp call into another BPF program, eBPF only
	CallOp = 0x80
	// ExitOp exit program
	ExitOp = 0x90
)

// Source bitmask
const (
	// SrcCode from what address is the value coming
	SrcCode = 0x08
	// ImmSrc src is from constant
	ImmSrc = 0x00
	// RegSrc src is from register
	RegSrc = 0x08
)

// ALU64 instructions
// alu/alu64/jmp opcode structure:
// msb      lsb
// +----+-+---+
// |op  |s|cls|
// +----+-+---+
// If the s bit is zero, then the source operand is imm,
// If s is one, then the source operand is src.
// ALU Instructions 64 bit, eBPF only
const (
	// AddImm  add dst, imm   |  dst += imm
	AddImm = 0x07
	// AddSrc  add dst, src   |  dst += src
	AddSrc = 0x0f
	// SubImm  sub dst, imm   |  dst -= imm
	SubImm = 0x17
	// SubSrc  sub dst, src   |  dst -= src
	SubSrc = 0x1f
	// MulImm  mul dst, imm   |  dst *= imm
	MulImm = 0x27
	// MulSrc  mul dst, src   |  dst *= src
	MulSrc = 0x2f
	// DivImm  div dst, imm   |  dst /= imm
	DivImm = 0x37
	// DivSrc  div dst, src   |  dst /= src
	DivSrc = 0x3f
	// OrImm   or dst, imm    |  dst  |= imm
	OrImm = 0x47
	// OrSrc   or dst, src    |  dst  |= src
	OrSrc = 0x4f
	// AndImm  and dst, imm   |  dst &= imm
	AndImm = 0x57
	// AndSrc  and dst, src   |  dst &= src
	AndSrc = 0x5f
	// LShImm  lsh dst, imm   |  dst <<= imm
	LShImm = 0x67
	// LShSrc  lsh dst, src   |  dst <<= src
	LShSrc = 0x6f
	// RShImm  rsh dst, imm   |  dst >>= imm (logical)
	RShImm = 0x77
	// RShSrc  rsh dst, src   |  dst >>= src (logical)
	RShSrc = 0x7f
	// Neg     neg dst        |  dst = -dst
	Neg = 0x87
	// ModImm  mod dst, imm   |  dst %= imm
	ModImm = 0x97
	// ModSrc  mod dst, src   |  dst %= src
	ModSrc = 0x9f
	// XorImm  xor dst, imm   |  dst ^= imm
	XorImm = 0xa7
	// XorSrc  xor dst, src   |  dst ^= src
	XorSrc = 0xaf
	// MovImm  mov dst, imm   |  dst = imm
	MovImm = 0xb7
	// MovSrc  mov dst, src   |  dst = src
	MovSrc = 0xbf
	// ArShImm arsh dst, imm  |  dst >>= imm (arithmetic)
	ArShImm = 0xc7
	// ArShSrc arsh dst, src  |  dst >>= src (arithmetic)
	ArShSrc = 0xcf
)

// ALU Instructions 32 bit
// These instructions use only the lower 32 bits of their
// operands and zero the upper 32 bits of the destination register.
const (
	// Add32Imm add32 dst, imm  |  dst += imm
	Add32Imm = 0x04
	// Add32Src add32 dst, src  |  dst += src
	Add32Src = 0x0c
	// Sub32Imm sub32 dst, imm  |  dst -= imm
	Sub32Imm = 0x14
	// Sub32Src sub32 dst, src  |  dst -= src
	Sub32Src = 0x1c
	// Mul32Imm mul32 dst, imm  |  dst *= imm
	Mul32Imm = 0x24
	// Mul32Src mul32 dst, src  |  dst *= src
	Mul32Src = 0x2c
	// Div32Imm div32 dst, imm  |  dst /= imm
	Div32Imm = 0x34
	// Div32Src div32 dst, src  |  dst /= src
	Div32Src = 0x3c
	// Or32Imm  or32 dst, imm   |  dst |= imm
	Or32Imm = 0x44
	// Or32Src  or32 dst, src   |  dst |= src
	Or32Src = 0x4c
	// And32Imm and32 dst, imm  |  dst &= imm
	And32Imm = 0x54
	// And32Src and32 dst, src  |  dst &= src
	And32Src = 0x5c
	// LSh32Imm lsh32 dst, imm  |  dst <<= imm
	LSh32Imm = 0x64
	// LSh32Src lsh32 dst, src  |  dst <<= src
	LSh32Src = 0x6c
	// RSh32Imm rsh32 dst, imm  |  dst >>= imm (logical)
	RSh32Imm = 0x74
	// RSh32Src rsh32 dst, src  |  dst >>= src (logical)
	RSh32Src = 0x7c
	// Neg32    neg32 dst       |  dst = -dst
	Neg32 = 0x84
	// Mod32Imm mod32 dst, imm  |  dst %= imm
	Mod32Imm = 0x94
	// Mod32Src mod32 dst, src  |  dst %= src
	Mod32Src = 0x9c
	// Xor32Imm xor32 dst, imm  |  dst ^= imm
	Xor32Imm = 0xa4
	// Xor32Src xor32 dst, src  |  dst ^= src
	Xor32Src = 0xac
	// Mov32Imm mov32 dst, imm  |  dst eBPF only
	Mov32Imm = 0xb4
	// Mov32Src mov32 dst, src  |  dst eBPF only
	Mov32Src = 0xbc
)

// Byteswap Instructions
const (
	// LE16 le16 dst, imm == 16  |  dst = htole16(dst)
	LE16 = 0xd4
	// LE32 le32 dst, imm == 32  |  dst = htole32(dst)
	LE32 = 0xd4
	// LE64 le64 dst, imm == 64  |  dst = htole64(dst)
	LE64 = 0xd4
	// BE16 be16 dst, imm == 16  |  dst = htobe16(dst)
	BE16 = 0xdc
	// BE32 be32 dst, imm == 32  |  dst = htobe32(dst)
	BE32 = 0xdc
	// BE64 be64 dst, imm == 64  |  dst = htobe64(dst)
	BE64 = 0xdc
)

// Memory Instructions
const (
	// LdDW      lddw (src), dst, imm   |  dst = *imm
	LdDW = 0x18
	// XAddStSrc xadd dst, src          |  *dst += src
	XAddStSrc = 0xdb
	// LdAbsB    ldabsb imm             |  r0 = (uint8_t *) (mem + imm)
	LdAbsB = 0x30
	// LdXW      ldxw dst, [src+off]    |  dst = *(uint32_t *) (src + off)
	LdXW = 0x61
	// LdXH      ldxh dst, [src+off]    |  dst = *(uint16_t *) (src + off)
	LdXH = 0x69
	// LdXB      ldxb dst, [src+off]    |  dst = *(uint8_t *) (src + off)
	LdXB = 0x71
	// LdXDW     ldxdw dst, [src+off]   |  dst = *(uint64_t *) (src + off)
	LdXDW = 0x79
	// StB       stb [dst+off], imm     |  *(uint8_t *) (dst + off) = imm
	StB = 0x72
	// StH       sth [dst+off], imm     |  *(uint16_t *) (dst + off) = imm
	StH = 0x6a
	// StW       stw [dst+off], imm     |  *(uint32_t *) (dst + off) = imm
	StW = 0x62
	// StDW      stdw [dst+off], imm    |  *(uint64_t *) (dst + off) = imm
	StDW = 0x7a
	// StXB      stxb [dst+off], src    |  *(uint8_t *) (dst + off) = src
	StXB = 0x73
	// StXH      stxh [dst+off], src    |  *(uint16_t *) (dst + off) = src
	StXH = 0x6b
	// StXW      stxw [dst+off], src    |  *(uint32_t *) (dst + off) = src
	StXW = 0x63
	// StXDW     stxdw [dst+off], src   |  *(uint64_t *) (dst + off) = src
	StXDW = 0x7b
	// LdAbsH  ldabsh imm             |  r0 = (uint16_t *) (imm)
	// Abs and Ind reference memory directly. This is always the context,
	// of whatever the eBPF program is. For example in a sock filter program
	// the memory context is the sk_buff struct.
	LdAbsH = 0x28
	// LdAbsW  ldabsw imm             |  r0 = (uint32_t *) (imm)
	LdAbsW = 0x20
	// LdAbsDW ldabsdw imm            |  r0 = (uint64_t *) (imm)
	LdAbsDW = 0x38
	// LdIndB  ldindb src, dst, imm   |  dst = (uint64_t *) (src + imm)
	LdIndB = 0x50
	// LdIndH  ldindh src, dst, imm   |  dst = (uint16_t *) (src + imm)
	LdIndH = 0x48
	// LdIndW  ldindw src, dst, imm   |  dst = (uint32_t *) (src + imm)
	LdIndW = 0x40
	// LdIndDW ldinddw src, dst, imm  |  dst = (uint64_t *) (src + imm)
	LdIndDW = 0x58
)

// Branch Instructions
const (
	// Ja      ja +off             |  PC += off
	Ja = 0x05
	// JEqImm  jeq dst, imm, +off  |  PC += off if dst == imm
	JEqImm = 0x15
	// JEqSrc  jeq dst, src, +off  |  PC += off if dst == src
	JEqSrc = 0x1d
	// JGTImm  jgt dst, imm, +off  |  PC += off if dst > imm
	JGTImm = 0x25
	// JGTSrc  jgt dst, src, +off  |  PC += off if dst > src
	JGTSrc = 0x2d
	// JGEImm  jge dst, imm, +off  |  PC += off if dst >= imm
	JGEImm = 0x35
	// JGESrc  jge dst, src, +off  |  PC += off if dst >= src
	JGESrc = 0x3d
	// JSETImm jset dst, imm, +off |  PC += off if dst & imm
	JSETImm = 0x45
	// JSETSrc jset dst, src, +off |  PC += off if dst & src
	JSETSrc = 0x4d
	// JNEImm  jne dst, imm, +off  |  PC += off if dst != imm
	JNEImm = 0x55
	// JNESrc  jne dst, src, +off  |  PC += off if dst != src
	JNESrc = 0x5d
	// JSGTImm jsgt dst, imm, +off |  PC += off if dst > imm (signed)
	JSGTImm = 0x65
	// JSGTSrc jsgt dst, src, +off |  PC += off if dst > src (signed)
	JSGTSrc = 0x6d
	// JSGEImm jsge dst, imm, +off |  PC += off if dst >= imm (signed)
	JSGEImm = 0x75
	// JSGESrc jsge dst, src, +off |  PC += off if dst >= src (signed)
	JSGESrc = 0x7d
	// Call    call imm            |  Function call
	Call = 0x85
	// Exit    exit                |  return r0
	Exit = 0x95
)

// Register register type
type Register uint8

const (

	// Reg0   - return value from in-kernel function, and exit value for eBPF program
	Reg0 = Register(iota)
	// Reg1 - arguments 0 from eBPF program to in-kernel function
	Reg1
	// Reg2 - arguments 1 from eBPF program to in-kernel function
	Reg2
	// Reg3 - arguments 2 from eBPF program to in-kernel function
	Reg3
	// Reg4 - arguments 3 from eBPF program to in-kernel function
	Reg4
	// Reg5 - arguments 4 from eBPF program to in-kernel function
	Reg5
	// Reg6 - callee 0 saved registers that in-kernel function will preserve
	Reg6
	// Reg7 - callee 1 saved registers that in-kernel function will preserve
	Reg7
	// Reg8 - callee 2 saved registers that in-kernel function will preserve
	Reg8
	// Reg9 - callee 3 saved registers that in-kernel function will preserve
	Reg9
	// Reg10  - read-only frame pointer to access stack
	Reg10
	// RegFP (alias of Reg10)  - read-only frame pointer to access stack
	RegFP = Reg10
)

func (r Register) String() string {
	v := uint8(r)
	if v == 10 {
		return "rfp"
	}
	return fmt.Sprintf("r%d", v)
}

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

// eBPF build-in functions
const (
	// MapLookupElement - void *map_lookup_elem(&map, &key)
	// Return: Map value or NULL
	MapLookupElement = int32(iota + 1)
	// MapUpdateElement - int map_update_elem(&map, &key, &value, flags)
	// Return: 0 on success or negative error
	MapUpdateElement
	// MapDeleteElement - int map_delete_elem(&map, &key)
	// Return: 0 on success or negative error
	MapDeleteElement
	// ProbeRead - int bpf_probe_read(void *dst, int size, void *src)
	// Return: 0 on success or negative error
	ProbeRead
	// KtimeGetNS - u64 bpf_ktime_get_ns(void)
	// Return: current ktime
	KtimeGetNS
	// TracePrintk - int bpf_trace_printk(const char *fmt, int fmt_size, ...)
	// Return: length of buffer written or negative error
	TracePrintk
	// GetPRandomu32 - u32 prandom_u32(void)
	// Return: random value
	GetPRandomu32
	// GetSMPProcessorID - u32 raw_smp_processor_id(void)
	// Return: SMP processor ID
	GetSMPProcessorID
	// SKBStoreBytes - skb_store_bytes(skb, offset, from, len, flags)
	// store bytes into packet
	// @skb: pointer to skb
	// @offset: offset within packet from skb->mac_header
	// @from: pointer where to copy bytes from
	// @len: number of bytes to store into packet
	// @flags: bit 0 - if true, recompute skb->csum
	//         other bits - reserved
	// Return: 0 on success
	SKBStoreBytes
	// CSUMReplaceL3 - l3_csum_replace(skb, offset, from, to, flags)
	// recompute IP checksum
	// @skb: pointer to skb
	// @offset: offset within packet where IP checksum is located
	// @from: old value of header field
	// @to: new value of header field
	// @flags: bits 0-3 - size of header field
	//         other bits - reserved
	// Return: 0 on success
	CSUMReplaceL3
	// CSUMReplaceL4 - l4_csum_replace(skb, offset, from, to, flags)
	// recompute TCP/UDP checksum
	// @skb: pointer to skb
	// @offset: offset within packet where TCP/UDP checksum is located
	// @from: old value of header field
	// @to: new value of header field
	// @flags: bits 0-3 - size of header field
	//         bit 4 - is pseudo header
	//         other bits - reserved
	// Return: 0 on success
	CSUMReplaceL4
	// TailCall - int bpf_tail_call(ctx, prog_array_map, index)
	// jump into another BPF program
	// @ctx: context pointer passed to next program
	// @prog_array_map: pointer to map which type is BPF_MAP_TYPE_PROG_ARRAY
	// @index: index inside array that selects specific program to run
	// Return: 0 on success or negative error
	TailCall
	// CloneRedirect - int bpf_clone_redirect(skb, ifindex, flags)
	// redirect to another netdev
	// @skb: pointer to skb
	// @ifindex: ifindex of the net device
	// @flags: bit 0 - if set, redirect to ingress instead of egress
	//         other bits - reserved
	// Return: 0 on success or negative error
	CloneRedirect
	// GetCurrentPIDTGID - u64 bpf_get_current_pid_tgid(void)
	// Return: current->tgid << 32 | current->pid
	GetCurrentPIDTGID
	// GetCurrentUIDGID - u64 bpf_get_current_uid_gid(void)
	// Return: current_gid << 32 | current_uid
	GetCurrentUIDGID
	// GetCurrentComm - int bpf_get_current_comm(char *buf, int size_of_buf) - stores current->comm into buf
	// Return: 0 on success or negative error
	GetCurrentComm
	// GetCGroupClassID - u32 bpf_get_cgroup_classid(skb)
	// retrieve a proc's classid
	// @skb: pointer to skb
	// Return: classid if != 0
	GetCGroupClassID
	// SKBVlanPush - int bpf_skb_vlan_push(skb, vlan_proto, vlan_tci)
	// Return: 0 on success or negative error
	SKBVlanPush
	// SKBVlanPop - int bpf_skb_vlan_pop(skb)
	// Return: 0 on success or negative error
	SKBVlanPop
	// SKBGetTunnelKey - int bpf_skb_get_tunnel_key(skb, key, size, flags)
	// retrieve or populate tunnel metadata
	// @skb: pointer to skb
	// @key: pointer to 'struct bpf_tunnel_key'
	// @size: size of 'struct bpf_tunnel_key'
	// @flags: room for future extensions
	// Return: 0 on success or negative error
	SKBGetTunnelKey
	// SKBSetTunnelKey - int bpf_skb_set_tunnel_key(skb, key, size, flags)
	// retrieve or populate tunnel metadata
	// @skb: pointer to skb
	// @key: pointer to 'struct bpf_tunnel_key'
	// @size: size of 'struct bpf_tunnel_key'
	// @flags: room for future extensions
	// Return: 0 on success or negative error
	SKBSetTunnelKey
	// PerfEventRead - u64 bpf_perf_event_read(map, flags)
	// read perf event counter value
	// @map: pointer to perf_event_array map
	// @flags: index of event in the map or bitmask flags
	// Return: value of perf event counter read or error code
	PerfEventRead
	// Redirect - int bpf_redirect(ifindex, flags)
	// redirect to another netdev
	// @ifindex: ifindex of the net device
	// @flags: bit 0 - if set, redirect to ingress instead of egress
	//         other bits - reserved
	// Return: TC_ACT_REDIRECT
	Redirect
	// GetRouteRealm - u32 bpf_get_route_realm(skb)
	// retrieve a dst's tclassid
	// @skb: pointer to skb
	// Return: realm if != 0
	GetRouteRealm
	// PerfEventOutput - int bpf_perf_event_output(ctx, map, flags, data, size)
	// output perf raw sample
	// @ctx: struct pt_regs*
	// @map: pointer to perf_event_array map
	// @flags: index of event in the map or bitmask flags
	// @data: data on stack to be output as raw data
	// @size: size of data
	// Return: 0 on success or negative error
	PerfEventOutput
	// GetStackID - int bpf_get_stackid(ctx, map, flags)
	// walk user or kernel stack and return id
	// @ctx: struct pt_regs*
	// @map: pointer to stack_trace map
	// @flags: bits 0-7 - numer of stack frames to skip
	//         bit 8 - collect user stack instead of kernel
	//         bit 9 - compare stacks by hash only
	//         bit 10 - if two different stacks hash into the same stackid
	//                  discard old
	//         other bits - reserved
	// Return: >= 0 stackid on success or negative error
	GetStackID
	// CsumDiff - s64 bpf_csum_diff(from, from_size, to, to_size, seed)
	// calculate csum diff
	// @from: raw from buffer
	// @from_size: length of from buffer
	// @to: raw to buffer
	// @to_size: length of to buffer
	// @seed: optional seed
	// Return: csum result or negative error code
	CsumDiff
	// SKBGetTunnelOpt - int bpf_skb_get_tunnel_opt(skb, opt, size)
	// retrieve tunnel options metadata
	// @skb: pointer to skb
	// @opt: pointer to raw tunnel option data
	// @size: size of @opt
	// Return: option size
	SKBGetTunnelOpt
	// SKBSetTunnelOpt - int bpf_skb_set_tunnel_opt(skb, opt, size)
	// populate tunnel options metadata
	// @skb: pointer to skb
	// @opt: pointer to raw tunnel option data
	// @size: size of @opt
	// Return: 0 on success or negative error
	SKBSetTunnelOpt
	// SKBChangeProto - int bpf_skb_change_proto(skb, proto, flags)
	// Change protocol of the skb. Currently supported is v4 -> v6,
	// v6 -> v4 transitions. The helper will also resize the skb. eBPF
	// program is expected to fill the new headers via skb_store_bytes
	// and lX_csum_replace.
	// @skb: pointer to skb
	// @proto: new skb->protocol type
	// @flags: reserved
	// Return: 0 on success or negative error
	SKBChangeProto
	// SKBChangeType - int bpf_skb_change_type(skb, type)
	// Change packet type of skb.
	// @skb: pointer to skb
	// @type: new skb->pkt_type type
	// Return: 0 on success or negative error
	SKBChangeType
	// SKBUnderCGroup - int bpf_skb_under_cgroup(skb, map, index)
	// Check cgroup2 membership of skb
	// @skb: pointer to skb
	// @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
	// @index: index of the cgroup in the bpf_map
	// Return:
	//   == 0 skb failed the cgroup2 descendant test
	//   == 1 skb succeeded the cgroup2 descendant test
	//    < 0 error
	SKBUnderCGroup
	// GetHashRecalc - u32 bpf_get_hash_recalc(skb)
	// Retrieve and possibly recalculate skb->hash.
	// @skb: pointer to skb
	// Return: hash
	GetHashRecalc
	// GetCurrentTask - u64 bpf_get_current_task(void)
	// Returns current task_struct
	// Return: current
	GetCurrentTask
	// ProbeWriteUser - int bpf_probe_write_user(void *dst, void *src, int len)
	// safely attempt to write to a location
	// @dst: destination address in userspace
	// @src: source address on stack
	// @len: number of bytes to copy
	// Return: 0 on success or negative error
	ProbeWriteUser
	// CurrentTaskUnderCGroup - int bpf_current_task_under_cgroup(map, index)
	// Check cgroup2 membership of current task
	// @map: pointer to bpf_map in BPF_MAP_TYPE_CGROUP_ARRAY type
	// @index: index of the cgroup in the bpf_map
	// Return:
	//   == 0 current failed the cgroup2 descendant test
	//   == 1 current succeeded the cgroup2 descendant test
	//    < 0 error
	CurrentTaskUnderCGroup
	// SKBChangeTail - int bpf_skb_change_tail(skb, len, flags)
	// The helper will resize the skb to the given new size, to be used f.e.
	// with control messages.
	// @skb: pointer to skb
	// @len: new skb length
	// @flags: reserved
	// Return: 0 on success or negative error
	SKBChangeTail
	// SKBPullData - int bpf_skb_pull_data(skb, len)
	// The helper will pull in non-linear data in case the skb is non-linear
	// and not all of len are part of the linear section. Only needed for
	// read/write with direct packet access.
	// @skb: pointer to skb
	// @Len: len to make read/writeable
	// Return: 0 on success or negative error
	SKBPullData
	// CSUMUpdate - s64 bpf_csum_update(skb, csum)
	// Adds csum into skb->csum in case of CHECKSUM_COMPLETE.
	// @skb: pointer to skb
	// @csum: csum to add
	// Return: csum on success or negative error
	CSUMUpdate
	// SetHashInvalid - void bpf_set_hash_invalid(skb)
	// Invalidate current skb->hash.
	// @skb: pointer to skb
	SetHashInvalid
	// GetNUMANodeID - int bpf_get_numa_node_id()
	// Return: Id of current NUMA node.
	GetNUMANodeID
	// SKBChangeHead - int bpf_skb_change_head()
	// Grows headroom of skb and adjusts MAC header offset accordingly.
	// Will extends/reallocae as required automatically.
	// May change skb data pointer and will thus invalidate any check
	// performed for direct packet access.
	// @skb: pointer to skb
	// @len: length of header to be pushed in front
	// @flags: Flags (unused for now)
	// Return: 0 on success or negative error
	SKBChangeHead
	// XDPAdjustHead - int bpf_xdp_adjust_head(xdp_md, delta)
	// Adjust the xdp_md.data by delta
	// @xdp_md: pointer to xdp_md
	// @delta: An positive/negative integer to be added to xdp_md.data
	// Return: 0 on success or negative on error
	XDPAdjustHead
	// ProbeReadStr - int bpf_probe_read_str(void *dst, int size, const void *unsafe_ptr)
	// Copy a NUL terminated string from unsafe address. In case the string
	// length is smaller than size, the target is not padded with further NUL
	// bytes. In case the string length is larger than size, just count-1
	// bytes are copied and the last byte is set to NUL.
	// @dst: destination address
	// @size: maximum number of bytes to copy, including the trailing NUL
	// @unsafe_ptr: unsafe address
	// Return:
	//   > 0 length of the string including the trailing NUL on success
	//   < 0 error
	ProbeReadStr
	// GetSocketCookie - u64 bpf_get_socket_cookie(skb)
	// Get the cookie for the socket stored inside sk_buff.
	// @skb: pointer to skb
	// Return: 8 Bytes non-decreasing number on success or 0 if the socket
	// field is missing inside sk_buff
	GetSocketCookie
	// GetSocketUID - u32 bpf_get_socket_uid(skb)
	// Get the owner uid of the socket stored inside sk_buff.
	// @skb: pointer to skb
	// Return: uid of the socket owner on success or overflowuid if failed.
	GetSocketUID
	// SetHash - u32 bpf_set_hash(skb, hash)
	// Set full skb->hash.
	// @skb: pointer to skb
	// @hash: hash to set
	SetHash
	// SetSockOpt - int bpf_setsockopt(bpf_socket, level, optname, optval, optlen)
	// Calls setsockopt. Not all opts are available, only those with
	// integer optvals plus TCP_CONGESTION.
	// Supported levels: SOL_SOCKET and IPROTO_TCP
	// @bpf_socket: pointer to bpf_socket
	// @level: SOL_SOCKET or IPROTO_TCP
	// @optname: option name
	// @optval: pointer to option value
	// @optlen: length of optval in byes
	// Return: 0 or negative error
	SetSockOpt
	// SKBAdjustRoom - int bpf_skb_adjust_room(skb, len_diff, mode, flags)
	// Grow or shrink room in sk_buff.
	// @skb: pointer to skb
	// @len_diff: (signed) amount of room to grow/shrink
	// @mode: operation mode (enum bpf_adj_room_mode)
	// @flags: reserved for future use
	// Return: 0 on success or negative error code
	SKBAdjustRoom
)

func getFuncStr(callNo int32) string {
	var s string
	switch callNo {
	case MapLookupElement:
		s = "MapLookupElement"
	case MapUpdateElement:
		s = "MapUpdateElement"
	case MapDeleteElement:
		s = "MapDeleteElement"
	case ProbeRead:
		s = "ProbeRead"
	case KtimeGetNS:
		s = "KtimeGetNS"
	case TracePrintk:
		s = "TracePrintk"
	case GetPRandomu32:
		s = "GetPRandomu32"
	case GetSMPProcessorID:
		s = "GetSMPProcessorID"
	case SKBStoreBytes:
		s = "SKBStoreBytes"
	case CSUMReplaceL3:
		s = "CSUMReplaceL3"
	case CSUMReplaceL4:
		s = "CSUMReplaceL4"
	case TailCall:
		s = "TailCall"
	case CloneRedirect:
		s = "CloneRedirect"
	case GetCurrentPIDTGID:
		s = "GetCurrentPIDTGID"
	case GetCurrentUIDGID:
		s = "GetCurrentUIDGID"
	case GetCurrentComm:
		s = "GetCurrentComm"
	case GetCGroupClassID:
		s = "GetCGroupClassID"
	case SKBVlanPush:
		s = "SKBVlanPush"
	case SKBVlanPop:
		s = "SKBVlanPop"
	case SKBGetTunnelKey:
		s = "SKBGetTunnelKey"
	case SKBSetTunnelKey:
		s = "SKBSetTunnelKey"
	case PerfEventRead:
		s = "PerfEventRead"
	case Redirect:
		s = "Redirect"
	case GetRouteRealm:
		s = "GetRouteRealm"
	case PerfEventOutput:
		s = "PerfEventOutput"
	case GetStackID:
		s = "GetStackID"
	case CsumDiff:
		s = "CsumDiff"
	case SKBGetTunnelOpt:
		s = "SKBGetTunnelOpt"
	case SKBSetTunnelOpt:
		s = "SKBSetTunnelOpt"
	case SKBChangeProto:
		s = "SKBChangeProto"
	case SKBChangeType:
		s = "SKBChangeType"
	case SKBUnderCGroup:
		s = "SKBUnderCGroup"
	case GetHashRecalc:
		s = "GetHashRecalc"
	case GetCurrentTask:
		s = "GetCurrentTask"
	case ProbeWriteUser:
		s = "ProbeWriteUser"
	case CurrentTaskUnderCGroup:
		s = "CurrentTaskUnderCGroup"
	case SKBChangeTail:
		s = "SKBChangeTail"
	case SKBPullData:
		s = "SKBPullData"
	case CSUMUpdate:
		s = "CSUMUpdate"
	case SetHashInvalid:
		s = "SetHashInvalid"
	case GetNUMANodeID:
		s = "GetNUMANodeID"
	case SKBChangeHead:
		s = "SKBChangeHead"
	case XDPAdjustHead:
		s = "XDPAdjustHead"
	case ProbeReadStr:
		s = "ProbeReadStr"
	case GetSocketCookie:
		s = "GetSocketCookie"
	case GetSocketUID:
		s = "GetSocketUID"
	case SetHash:
		s = "SetHash"
	case SetSockOpt:
		s = "SetSockOpt"
	case SKBAdjustRoom:
		s = "SKBAdjustRoom"
	default:
		return fmt.Sprintf("uknown function call: %d", callNo)
	}
	return s
}

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

type bitField uint8

func (r *bitField) SetPart1(v Register) {
	*r = bitField((uint8(*r) & 0xF0) | uint8(v))
}

func (r *bitField) SetPart2(v Register) {
	*r = bitField((uint8(*r) & 0xF) | (uint8(v) << 4))
}

func (r bitField) GetPart1() Register {
	return Register(uint8(r) & 0xF)
}

func (r bitField) GetPart2() Register {
	return Register(uint8(r) >> 4)
}

// Instructions is the lowest level construct for a BPF snippet in array.
type Instructions []*BPFInstruction

func (inss Instructions) String() string {
	return inss.StringIndent(0)
}

// StringIndent prints out BPF instructions in a human readable format
// with a specific indentation indentation level.
func (inss Instructions) StringIndent(r int) string {
	var buf bytes.Buffer
	indent := strings.Repeat("\t", r)
	for i, ins := range inss {
		buf.WriteString(fmt.Sprintf("%s%d: %s\n", indent, i, ins))
		extra := ins.extra
		i2 := 1
		for extra != nil {
			buf.WriteString(fmt.Sprintf("\t%sex-%d-%d: %s\n", indent, i, i2, extra))
			extra = extra.extra
		}
	}
	return buf.String()
}

// BPFInstruction represents the data
// of a specific eBPF instruction and how
// it will execute (opcode, registers, constant, offset, etc).
type BPFInstruction struct {
	OpCode      uint8
	DstRegister Register
	SrcRegister Register
	Offset      int16
	Constant    int32

	sectionName string
	extra       *BPFInstruction
}

type bpfInstruction struct {
	OpCode    uint8
	Registers bitField
	Offset    int16
	Constant  int32
}

var classMap = map[int]string{
	LdClass:    "Ld",
	LdXClass:   "LdX",
	StClass:    "St",
	StXClass:   "StX",
	ALUClass:   "ALU32",
	JmpClass:   "Jmp",
	RetClass:   "Rt",
	ALU64Class: "ALU64",
}

func (bpfi *BPFInstruction) String() string {
	var opStr string
	op := uint8(bpfi.OpCode)
	var class, dst, src, off, imm string
	var sBit uint8
	var alu32 string
	classCode := op & ClassCode
	switch classCode {
	case RetClass, LdClass, LdXClass, StClass, StXClass:
		class = classMap[int(classCode)]
		mode := ""
		xAdd := false
		dst = fmt.Sprintf(" dst: %s", bpfi.DstRegister)
		switch op & ModeCode {
		case ImmMode:
			mode = "Imm"
			imm = fmt.Sprintf(" imm: %d", bpfi.Constant)
		case AbsMode:
			mode = "Abs"
			dst = ""
			imm = fmt.Sprintf(" imm: %d", bpfi.Constant)
			off = ""
		case IndMode:
			mode = "Ind"
			src = fmt.Sprintf(" src: %s", bpfi.SrcRegister)
			imm = fmt.Sprintf(" imm: %d", bpfi.Constant)
			off = ""
		case MemMode:
			src = fmt.Sprintf(" src: %s", bpfi.SrcRegister)
			off = fmt.Sprintf(" off: %d", bpfi.Offset)
			imm = fmt.Sprintf(" imm: %d", bpfi.Constant)
		case LenMode:
			mode = "Len"
		case MshMode:
			mode = "Msh"
		case XAddMode:
			mode = "XAdd"
			src = fmt.Sprintf(" src: %s", bpfi.SrcRegister)
			xAdd = true
		}
		size := ""
		switch op & SizeCode {
		case DWSize:
			size = "DW"
		case WSize:
			size = "W"
		case HSize:
			size = "H"
		case BSize:
			size = "B"
		}
		if xAdd {
			opStr = fmt.Sprintf("%s%s", mode, class)
		}
		opStr = fmt.Sprintf("%s%s%s", class, mode, size)
	case ALU64Class, ALUClass:
		if classCode == ALUClass {
			alu32 = "32"
		}
		dst = fmt.Sprintf(" dst: %s", bpfi.DstRegister)
		sBit = op & SrcCode
		opSuffix := ""
		if sBit == ImmSrc {
			imm = fmt.Sprintf(" imm: %d", bpfi.Constant)
			opSuffix = "Imm"
		} else {
			src = fmt.Sprintf(" src: %s", bpfi.SrcRegister)
			opSuffix = "Src"
		}
		opPrefix := ""
		switch op & OpCode {
		case AddOp:
			opPrefix = "Add"
		case SubOp:
			opPrefix = "Sub"
		case MulOp:
			opPrefix = "Mul"
		case DivOp:
			opPrefix = "Div"
		case OrOp:
			opPrefix = "Or"
		case AndOp:
			opPrefix = "And"
		case LShOp:
			opPrefix = "LSh"
		case RShOp:
			opPrefix = "RSh"
		case NegOp:
			opPrefix = "Neg"
		case ModOp:
			opPrefix = "Mod"
		case XOrOp:
			opPrefix = "XOr"
		case MovOp:
			opPrefix = "Mov"
		case ArShOp:
			opPrefix = "ArSh"
		case EndFlag:
			alu32 = ""
			src = ""
			imm = fmt.Sprintf(" imm: %d", bpfi.Constant)
			opPrefix = "ToFromLe"
			if sBit == 1 {
				opPrefix = "ToFromBe"
			}
			opPrefix = ""
		}
		opStr = fmt.Sprintf("%s%s%s", opPrefix, alu32, opSuffix)
	case JmpClass:
		dst = fmt.Sprintf(" dst: %s", bpfi.DstRegister)
		off = fmt.Sprintf(" off: %d", bpfi.Offset)
		sBit = op & SrcCode
		opSuffix := ""
		if sBit == ImmSrc {
			imm = fmt.Sprintf(" imm: %d", bpfi.Constant)
			opSuffix = "Imm"
		} else {
			src = fmt.Sprintf(" src: %s", bpfi.SrcRegister)
			opSuffix = "Src"
		}
		opPrefix := ""
		switch op & ModOp {
		case JaOp:
			opPrefix = "Ja"
		case JEqOp:
			opPrefix = "JEq"
		case JGTOp:
			opPrefix = "JGT"
		case JGEOp:
			opPrefix = "JGE"
		case JSETOp:
			opPrefix = "JSET"
		case JNEOp:
			opPrefix = "JNE"
		case JSGTOp:
			opPrefix = "JSGT"
		case JSGEOp:
			opPrefix = "JSGE"
		case CallOp:
			imm = ""
			src = ""
			off = ""
			dst = ""
			opPrefix = "Call"
			opSuffix = fmt.Sprintf(" %s", getFuncStr(bpfi.Constant))
		case ExitOp:
			imm = ""
			src = ""
			off = ""
			dst = ""
			opSuffix = ""
			opPrefix = "Exit"
		}
		opStr = fmt.Sprintf("%s%s", opPrefix, opSuffix)
	}
	return fmt.Sprintf("op: %s%s%s%s%s", opStr, dst, src, off, imm)
}

// BPFIOp BPF instruction that stands alone (i.e. exit)
func BPFIOp(opCode uint8) *BPFInstruction {
	return &BPFInstruction{
		OpCode: opCode,
	}
}

// BPFIDst BPF instruction with a dst
func BPFIDst(opCode uint8, dst Register) *BPFInstruction {
	return &BPFInstruction{
		OpCode:      opCode,
		DstRegister: dst,
	}
}

// BPFIImm BPF Instruction with a constant
func BPFIImm(opCode uint8, imm int32) *BPFInstruction {
	return &BPFInstruction{
		OpCode:   opCode,
		Constant: imm,
	}
}

// BPFIDstOff BPF instruction with a dst, and offset
func BPFIDstOff(opCode uint8, dst Register, off int16) *BPFInstruction {
	return &BPFInstruction{
		OpCode: opCode,
		Offset: off,
	}
}

// BPFIDstImm BPF instruction with a dst, and constant
func BPFIDstImm(opCode uint8, dst Register, imm int32) *BPFInstruction {
	return &BPFInstruction{
		OpCode:      opCode,
		DstRegister: dst,
		Constant:    imm,
	}
}

// BPFIDstSrc BPF instruction with a dst, and src
func BPFIDstSrc(opCode uint8, dst, src Register) *BPFInstruction {
	return &BPFInstruction{
		OpCode:      opCode,
		DstRegister: dst,
		SrcRegister: src,
	}
}

// BPFIDstOffImm BPF instruction with a dst, offset, and constant
func BPFIDstOffImm(opCode uint8, dst Register, off int16, imm int32) *BPFInstruction {
	return &BPFInstruction{
		OpCode:      opCode,
		DstRegister: dst,
		Offset:      off,
		Constant:    imm,
	}
}

// BPFIDstOffSrc BPF instruction with a dst, offset, and src.
func BPFIDstOffSrc(opCode uint8, dst, src Register, off int16) *BPFInstruction {
	return &BPFInstruction{
		OpCode:      opCode,
		DstRegister: dst,
		SrcRegister: src,
		Offset:      off,
	}
}

// BPFIDstSrcImm BPF instruction with a dst, src, and constant
func BPFIDstSrcImm(opCode uint8, dst, src Register, imm int32) *BPFInstruction {
	return &BPFInstruction{
		OpCode:      opCode,
		DstRegister: dst,
		SrcRegister: src,
		Constant:    imm,
	}
}

// BPFIDstOffImmSrc BPF instruction with a dst, src, offset, and constant
func BPFIDstOffImmSrc(opCode uint8, dst, src Register, off int16, imm int32) *BPFInstruction {
	return &BPFInstruction{
		OpCode:      opCode,
		DstRegister: dst,
		SrcRegister: src,
		Offset:      off,
		Constant:    imm,
	}
}

// BPFILdMapFd loads a user space fd into a BPF program as a reference to a
// specific eBPF map.
func BPFILdMapFd(dst Register, imm int) *BPFInstruction {
	return BPFILdImm64Raw(dst, 1, uint64(imm))
}

func BPFILdImm64(dst Register, imm uint64) *BPFInstruction {
	return BPFILdImm64Raw(dst, 0, imm)
}

func BPFILdImm64Raw(dst, src Register, imm uint64) *BPFInstruction {
	bpfi := BPFIDstSrcImm(LdDW, dst, src, int32(uint32(imm)))
	bpfi.extra = BPFIImm(0, int32(imm>>32))
	return bpfi
}

func (bpfi *BPFInstruction) getCStructs() []bpfInstruction {
	var bf bitField
	var inss []bpfInstruction
	for extra := bpfi; extra != nil; extra = extra.extra {
		bf.SetPart1(extra.DstRegister)
		bf.SetPart2(extra.SrcRegister)
		inss = append(inss, bpfInstruction{
			OpCode:    extra.OpCode,
			Registers: bf,
			Offset:    extra.Offset,
			Constant:  extra.Constant,
		})
	}
	return inss
}
