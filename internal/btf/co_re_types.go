package btf

import "fmt"

const (
	coreSpecMaxLen = 64
)

type coreReloRecord struct {
	TypeId       TypeID
	AccessStrOff uint32
	ReloKind     COREReloKind
}

// CORERelocation represents a requested CO-RE relocation
type CORERelocation struct {
	Type
	Accessor string
	Kind     COREReloKind
	Result   *COREReloResult
}

func (cr CORERelocation) Format(f fmt.State, c rune) {
	if c != 's' && c != 'v' {
		fmt.Fprintf(f, "{UNKNOWN FORMAT '%c'}", c)
		return
	}

	fmt.Fprintf(f, "[%v] %s (%s) = %v", cr.Type, cr.Accessor, cr.Kind, cr.Result)
}

// COREReloKind is the type of CO-RE relocation
type COREReloKind uint32

const (
	reloFieldByteOffset COREReloKind = iota /* field byte offset */
	reloFieldByteSize                       /* field size in bytes */
	reloFieldExists                         /* field existence in target kernel */
	reloFieldSigned                         /* field signedness (0 - unsigned, 1 - signed) */
	reloFieldLShiftU64                      /* bitfield-specific left bitshift */
	reloFieldRShiftU64                      /* bitfield-specific right bitshift */
	reloTypeIDLocal                         /* type ID in local BPF object */
	reloTypeIDTarget                        /* type ID in target kernel */
	reloTypeExists                          /* type existence in target kernel */
	reloTypeSize                            /* type size in bytes */
	reloEnumvalExists                       /* enum value existence in target kernel */
	reloEnumvalValue                        /* enum value integer value */
)

func (k COREReloKind) String() string {
	switch k {
	case reloFieldByteOffset:
		return "byte_off"
	case reloFieldByteSize:
		return "byte_sz"
	case reloFieldExists:
		return "field_exists"
	case reloFieldSigned:
		return "signed"
	case reloFieldLShiftU64:
		return "lshift_u64"
	case reloFieldRShiftU64:
		return "rshift_u64"
	case reloTypeIDLocal:
		return "local_type_id"
	case reloTypeIDTarget:
		return "target_type_id"
	case reloTypeExists:
		return "type_exists"
	case reloTypeSize:
		return "type_size"
	case reloEnumvalExists:
		return "enumval_exists"
	case reloEnumvalValue:
		return "enumval_value"
	default:
		return "unknown"
	}
}

type coreAccessor struct {
	typ  Type
	idx  uint32
	name Name
}

func (acc coreAccessor) Format(f fmt.State, c rune) {
	if c != 's' && c != 'v' {
		fmt.Fprintf(f, "{UNKNOWN FORMAT '%c'}", c)
		return
	}

	fmt.Fprintf(f, "[%v] '%s' idx=%d", acc.typ, acc.name, acc.idx)
}

type coreSpec struct {
	spec      []*coreAccessor
	rootType  Type
	reloKind  COREReloKind
	rawSpec   []uint32
	bitOffset uint32
}

func (cs coreSpec) Format(f fmt.State, c rune) {
	if c != 's' && c != 'v' {
		fmt.Fprintf(f, "{UNKNOWN FORMAT '%c'}", c)
		return
	}

	fmt.Fprintf(f, "[%v] %v (%s) offset=%d", cs.rootType, cs.rawSpec, cs.reloKind, cs.bitOffset)
	if f.Flag('+') {
		for _, s := range cs.spec {
			fmt.Fprintf(f, "\n\t%v", s)
		}
	}
}

// COREReloResult is the result of a CO-RE relocation
type COREReloResult struct {
	// OrigVal is the expected value in the instruction, unless Validate == false
	OrigVal uint32
	// NewVal is the new value that needs to be patched up to
	NewVal uint32
	// Poison flags if the relocation was unsuccessful, used to poison an instruction, but not fail loading
	Poison bool
	// Validate indicates whether we can compare OrigVal against the value in the instruction being relocated
	Validate bool
}

func (rr COREReloResult) Format(f fmt.State, c rune) {
	if c != 's' && c != 'v' {
		fmt.Fprintf(f, "{UNKNOWN FORMAT '%c'}", c)
		return
	}

	if rr.Poison {
		fmt.Fprintf(f, "POISON")
	} else {
		fmt.Fprintf(f, "%d => %d validate=%t", rr.OrigVal, rr.NewVal, rr.Validate)
	}
}

func (k COREReloKind) isFieldBased() bool {
	switch k {
	case reloFieldByteOffset, reloFieldByteSize, reloFieldExists, reloFieldSigned, reloFieldLShiftU64, reloFieldRShiftU64:
		return true
	default:
		return false
	}
}

func (k COREReloKind) isTypeBased() bool {
	switch k {
	case reloTypeIDLocal, reloTypeIDTarget, reloTypeExists, reloTypeSize:
		return true
	default:
		return false
	}
}

func (k COREReloKind) isEnumValBased() bool {
	switch k {
	case reloEnumvalExists, reloEnumvalValue:
		return true
	default:
		return false
	}
}
