package asm

//go:generate go run golang.org/x/tools/cmd/stringer@latest -output load_store_string.go -type=Mode,Size,Atomic

// Mode for load and store operations
//
//	msb      lsb
//	+---+--+---+
//	|MDE|sz|cls|
//	+---+--+---+
type Mode uint8

const modeMask OpCode = 0xe0

const (
	// InvalidMode is returned by getters when invoked
	// on non load / store OpCodes
	InvalidMode Mode = 0xff
	// ImmMode - immediate value
	ImmMode Mode = 0x00
	// AbsMode - immediate value + offset
	AbsMode Mode = 0x20
	// IndMode - indirect (imm+src)
	IndMode Mode = 0x40
	// MemMode - load from memory
	MemMode Mode = 0x60
	// MemSXMode - load from memory, sign extension
	MemSXMode Mode = 0x80
	// AtomicMode - add atomically across processors.
	AtomicMode Mode = 0xc0
)

const atomicMask OpCode = 0x01ff_0000

type Atomic uint32

const (
	InvalidAtomic Atomic = 0xffff_ffff
	// AddAtomic - add src to memory address dst atomically
	AddAtomic Atomic = Atomic(Add) << 16
	// FetchAddAtomic - add src to memory address at dst atomically, store old value in src
	FetchAddAtomic Atomic = AddAtomic | Fetch
	// AndAtomic - bitwise AND src with memory address at dst atomically
	AndAtomic Atomic = Atomic(And) << 16
	// FetchAndAtomic - bitwise AND src with memory address at dst atomically, store old value in src
	FetchAndAtomic Atomic = AndAtomic | Fetch
	// OrAtomic - bitwise OR src with memory address at dst atomically
	OrAtomic Atomic = Atomic(Or) << 16
	// FetchOrAtomic - bitwise OR src with memory address at dst atomically, store old value in src
	FetchOrAtomic Atomic = OrAtomic | Fetch
	// XorAtomic - bitwise XOR src with memory address at dst atomically
	XorAtomic Atomic = Atomic(Xor) << 16
	// FetchXorAtomic - bitwise XOR src with memory address at dst atomically, store old value in src
	FetchXorAtomic Atomic = XorAtomic | Fetch
	// FetchAtomicOp - load the old value into the src register
	Fetch Atomic = 0x0001_0000
	// XchgAtomic - atomically exchange the old value with the new value
	XchgAtomic Atomic = 0x00e0_0000 | Fetch
	// CmpXchgAtomic - atomically compare and exchange the old value with the new value
	CmpXchgAtomic Atomic = 0x00f0_0000 | Fetch
	// LdAcqAtomic - atomically load with acquire semantics
	LdAcqAtomic Atomic = 0x0100_0000
	// StRelAtomic - atomically store with release semantics
	StRelAtomic Atomic = 0x0110_0000
)

// Size of load and store operations
//
//	msb      lsb
//	+---+--+---+
//	|mde|SZ|cls|
//	+---+--+---+
type Size uint8

const sizeMask OpCode = 0x18

const (
	// InvalidSize is returned by getters when invoked
	// on non load / store OpCodes
	InvalidSize Size = 0xff
	// DWord - double word; 64 bits
	DWord Size = 0x18
	// Word - word; 32 bits
	Word Size = 0x00
	// Half - half-word; 16 bits
	Half Size = 0x08
	// Byte - byte; 8 bits
	Byte Size = 0x10
)

// Sizeof returns the size in bytes.
func (s Size) Sizeof() int {
	switch s {
	case DWord:
		return 8
	case Word:
		return 4
	case Half:
		return 2
	case Byte:
		return 1
	default:
		return -1
	}
}

// LoadMemOp returns the OpCode to load a value of given size from memory.
func LoadMemOp(size Size) OpCode {
	return OpCode(LdXClass).SetMode(MemMode).SetSize(size)
}

// LoadMemSXOp returns the OpCode to load a value of given size from memory sign extended.
func LoadMemSXOp(size Size) OpCode {
	return OpCode(LdXClass).SetMode(MemSXMode).SetSize(size)
}

// LoadMem emits `dst = *(size *)(src + offset)`.
func LoadMem(dst, src Register, offset int16, size Size) Instruction {
	return Instruction{
		OpCode: LoadMemOp(size),
		Dst:    dst,
		Src:    src,
		Offset: offset,
	}
}

// LoadMemSX emits `dst = *(size *)(src + offset)` but sign extends dst.
func LoadMemSX(dst, src Register, offset int16, size Size) Instruction {
	if size == DWord {
		return Instruction{OpCode: InvalidOpCode}
	}

	return Instruction{
		OpCode: LoadMemSXOp(size),
		Dst:    dst,
		Src:    src,
		Offset: offset,
	}
}

// LoadImmOp returns the OpCode to load an immediate of given size.
//
// As of kernel 4.20, only DWord size is accepted.
func LoadImmOp(size Size) OpCode {
	return OpCode(LdClass).SetMode(ImmMode).SetSize(size)
}

// LoadImm emits `dst = (size)value`.
//
// As of kernel 4.20, only DWord size is accepted.
func LoadImm(dst Register, value int64, size Size) Instruction {
	return Instruction{
		OpCode:   LoadImmOp(size),
		Dst:      dst,
		Constant: value,
	}
}

// LoadMapPtr stores a pointer to a map in dst.
func LoadMapPtr(dst Register, fd int) Instruction {
	if fd < 0 {
		return Instruction{OpCode: InvalidOpCode}
	}

	return Instruction{
		OpCode:   LoadImmOp(DWord),
		Dst:      dst,
		Src:      PseudoMapFD,
		Constant: int64(uint32(fd)),
	}
}

// LoadMapValue stores a pointer to the value at a certain offset of a map.
func LoadMapValue(dst Register, fd int, offset uint32) Instruction {
	if fd < 0 {
		return Instruction{OpCode: InvalidOpCode}
	}

	fdAndOffset := (uint64(offset) << 32) | uint64(uint32(fd))
	return Instruction{
		OpCode:   LoadImmOp(DWord),
		Dst:      dst,
		Src:      PseudoMapValue,
		Constant: int64(fdAndOffset),
	}
}

// LoadIndOp returns the OpCode for loading a value of given size from an sk_buff.
func LoadIndOp(size Size) OpCode {
	return OpCode(LdClass).SetMode(IndMode).SetSize(size)
}

// LoadInd emits `dst = ntoh(*(size *)(((sk_buff *)R6)->data + src + offset))`.
func LoadInd(dst, src Register, offset int32, size Size) Instruction {
	return Instruction{
		OpCode:   LoadIndOp(size),
		Dst:      dst,
		Src:      src,
		Constant: int64(offset),
	}
}

// LoadAbsOp returns the OpCode for loading a value of given size from an sk_buff.
func LoadAbsOp(size Size) OpCode {
	return OpCode(LdClass).SetMode(AbsMode).SetSize(size)
}

// LoadAbs emits `r0 = ntoh(*(size *)(((sk_buff *)R6)->data + offset))`.
func LoadAbs(offset int32, size Size) Instruction {
	return Instruction{
		OpCode:   LoadAbsOp(size),
		Dst:      R0,
		Constant: int64(offset),
	}
}

// StoreMemOp returns the OpCode for storing a register of given size in memory.
func StoreMemOp(size Size) OpCode {
	return OpCode(StXClass).SetMode(MemMode).SetSize(size)
}

// StoreMem emits `*(size *)(dst + offset) = src`
func StoreMem(dst Register, offset int16, src Register, size Size) Instruction {
	return Instruction{
		OpCode: StoreMemOp(size),
		Dst:    dst,
		Src:    src,
		Offset: offset,
	}
}

// StoreImmOp returns the OpCode for storing an immediate of given size in memory.
func StoreImmOp(size Size) OpCode {
	return OpCode(StClass).SetMode(MemMode).SetSize(size)
}

// StoreImm emits `*(size *)(dst + offset) = value`.
func StoreImm(dst Register, offset int16, value int64, size Size) Instruction {
	return Instruction{
		OpCode:   StoreImmOp(size),
		Dst:      dst,
		Offset:   offset,
		Constant: value,
	}
}

func AtomicOp(size Size, atomic Atomic, fetch bool) OpCode {
	switch atomic {
	case AddAtomic, AndAtomic, OrAtomic, XorAtomic:
		if fetch {
			atomic |= Fetch
		}

		switch size {
		case Byte, Half:
			// 8-bit and 16-bit atomic copy-modify-write atomics are not supported
			return InvalidOpCode
		}
	}

	return OpCode(StXClass).SetMode(AtomicMode).SetSize(size).SetAtomic(atomic)
}

// StoreXAddOp returns the OpCode to atomically add a register to a value in memory.
func StoreXAddOp(size Size) OpCode {
	return AtomicOp(size, AddAtomic, false)
}

// AtomicAnd atomically adds src to *(dst + offset), storing the old value in src if fetch is true.
func AtomicAdd(dst, src Register, size Size, offset int16, fetch bool) Instruction {
	return Instruction{
		OpCode: AtomicOp(size, AddAtomic, fetch),
		Dst:    dst,
		Src:    src,
		Offset: offset,
	}
}

// Alias for AtomicAdd
func StoreXAdd(dst, src Register, size Size) Instruction {
	return AtomicAdd(dst, src, size, 0, false)
}

// AtomicAnd atomically bitwise ANDs src with *(dst + offset), storing the old value in src if fetch is true.
func AtomicAnd(dst, src Register, size Size, offset int16, fetch bool) Instruction {
	return Instruction{
		OpCode: AtomicOp(size, AndAtomic, fetch),
		Dst:    dst,
		Src:    src,
		Offset: offset,
	}
}

// AtomicOr atomically bitwise ORs src with *(dst + offset), storing the old value in src if fetch is true.
func AtomicOr(dst, src Register, size Size, offset int16, fetch bool) Instruction {
	return Instruction{
		OpCode: AtomicOp(size, OrAtomic, fetch),
		Dst:    dst,
		Src:    src,
		Offset: offset,
	}
}

// AtomicXor atomically bitwise XORs src with *(dst + offset), storing the old value in src if fetch is true.
func AtomicXor(dst, src Register, size Size, offset int16, fetch bool) Instruction {
	return Instruction{
		OpCode: AtomicOp(size, XorAtomic, fetch),
		Dst:    dst,
		Src:    src,
		Offset: offset,
	}
}

// AtomicXchg atomically exchanges src with *(dst + offset), storing the old value in src if fetch is true.
func AtomicXchg(dst, src Register, size Size, offset int16, fetch bool) Instruction {
	return Instruction{
		OpCode: AtomicOp(size, XchgAtomic, fetch),
		Dst:    dst,
		Src:    src,
		Offset: offset,
	}
}

// AtomicCmpXchg atomically compares src with *(dst + offset), storing the old value in src if fetch is true.
func AtomicCmpXchg(dst, src Register, size Size, offset int16, fetch bool) Instruction {
	return Instruction{
		OpCode: AtomicOp(size, CmpXchgAtomic, fetch),
		Dst:    dst,
		Src:    src,
		Offset: offset,
	}
}

// AtomicStRel atomically stores src in *(dst + offset) with release semantics.
func AtomicStRel(dst, src Register, size Size, offset int16) Instruction {
	return Instruction{
		OpCode: AtomicOp(size, StRelAtomic, false),
		Dst:    dst,
		Src:    src,
		Offset: offset,
	}
}

// AtomicLdAcq atomically loads *(dst + offset) into src with acquire semantics.
func AtomicLdAcq(dst, src Register, size Size, offset int16) Instruction {
	return Instruction{
		OpCode: AtomicOp(size, LdAcqAtomic, false),
		Dst:    dst,
		Src:    src,
		Offset: offset,
	}
}
