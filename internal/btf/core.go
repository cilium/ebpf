package btf

import (
	"errors"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/asm"
)

// Code in this file is derived from libbpf, which is available under a BSD
// 2-Clause license.

// COREFixup is the result of computing a CO-RE relocation for a target.
type COREFixup struct {
	Kind   COREKind
	Local  uint32
	Target uint32
	Poison bool
}

func (f COREFixup) equal(other COREFixup) bool {
	return f.Local == other.Local && f.Target == other.Target
}

func (f COREFixup) String() string {
	if f.Poison {
		return fmt.Sprintf("%s=poison", f.Kind)
	}
	return fmt.Sprintf("%s=%d->%d", f.Kind, f.Local, f.Target)
}

func (f COREFixup) apply(ins *asm.Instruction) error {
	if f.Poison {
		return errors.New("can't poison individual instruction")
	}

	switch class := ins.OpCode.Class(); class {
	case asm.LdXClass, asm.StClass, asm.StXClass:
		if want := int16(f.Local); want != ins.Offset {
			return fmt.Errorf("invalid offset %d, expected %d", ins.Offset, want)
		}

		if f.Target > math.MaxInt16 {
			return fmt.Errorf("offset %d exceeds MaxInt16", f.Target)
		}

		ins.Offset = int16(f.Target)

	case asm.LdClass:
		if !ins.IsConstantLoad(asm.DWord) {
			return fmt.Errorf("not a dword-sized immediate load")
		}

		if want := int64(f.Local); want != ins.Constant {
			return fmt.Errorf("invalid immediate %d, expected %d", ins.Constant, want)
		}

		ins.Constant = int64(f.Target)

	case asm.ALUClass:
		if ins.OpCode.ALUOp() == asm.Swap {
			return fmt.Errorf("relocation against swap")
		}

		fallthrough

	case asm.ALU64Class:
		if src := ins.OpCode.Source(); src != asm.ImmSource {
			return fmt.Errorf("invalid source %s", src)
		}

		if want := int64(f.Local); want != ins.Constant {
			return fmt.Errorf("invalid immediate %d, expected %d", ins.Constant, want)
		}

		if f.Target > math.MaxInt32 {
			return fmt.Errorf("immediate %d exceeds MaxInt32", f.Target)
		}

		ins.Constant = int64(f.Target)

	default:
		return fmt.Errorf("invalid class %s", class)
	}

	return nil
}

func (f COREFixup) isNonExistant() bool {
	return f.Kind.checksForExistence() && f.Target == 0
}

type COREFixups map[uint64]COREFixup

// Apply a set of CO-RE relocations to a BPF program.
func (fs COREFixups) Apply(insns asm.Instructions) (asm.Instructions, error) {
	if len(fs) == 0 {
		cpy := make(asm.Instructions, len(insns))
		copy(cpy, insns)
		return insns, nil
	}

	cpy := make(asm.Instructions, 0, len(insns))
	iter := insns.Iterate()
	for iter.Next() {
		fixup, ok := fs[iter.Offset.Bytes()]
		if !ok {
			cpy = append(cpy, *iter.Ins)
			continue
		}

		ins := *iter.Ins
		if fixup.Poison {
			const badRelo = asm.BuiltinFunc(0xbad2310)

			cpy = append(cpy, badRelo.Call())
			if ins.OpCode.IsDWordLoad() {
				// 64 bit constant loads occupy two raw bpf instructions, so
				// we need to add another instruction as padding.
				cpy = append(cpy, badRelo.Call())
			}

			continue
		}

		if err := fixup.apply(&ins); err != nil {
			return nil, fmt.Errorf("instruction %d, offset %d: %s: %w", iter.Index, iter.Offset.Bytes(), fixup.Kind, err)
		}

		cpy = append(cpy, ins)
	}

	return cpy, nil
}

// COREKind is the type of CO-RE relocation
type COREKind uint32

const (
	reloFieldByteOffset COREKind = iota /* field byte offset */
	reloFieldByteSize                   /* field size in bytes */
	reloFieldExists                     /* field existence in target kernel */
	reloFieldSigned                     /* field signedness (0 - unsigned, 1 - signed) */
	reloFieldLShiftU64                  /* bitfield-specific left bitshift */
	reloFieldRShiftU64                  /* bitfield-specific right bitshift */
	reloTypeIDLocal                     /* type ID in local BPF object */
	reloTypeIDTarget                    /* type ID in target kernel */
	reloTypeExists                      /* type existence in target kernel */
	reloTypeSize                        /* type size in bytes */
	reloEnumvalExists                   /* enum value existence in target kernel */
	reloEnumvalValue                    /* enum value integer value */
)

func (k COREKind) String() string {
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

func (k COREKind) checksForExistence() bool {
	return k == reloEnumvalExists || k == reloTypeExists || k == reloFieldExists
}

func coreRelocate(local, target *Spec, relos coreRelos) (COREFixups, error) {
	if local.byteOrder != target.byteOrder {
		return nil, fmt.Errorf("can't relocate %s against %s", local.byteOrder, target.byteOrder)
	}

	var ids []TypeID
	relosByID := make(map[TypeID]coreRelos)
	result := make(COREFixups, len(relos))
	for _, relo := range relos {
		if relo.kind == reloTypeIDLocal {
			// Filtering out reloTypeIDLocal here makes our lives a lot easier
			// down the line, since it doesn't have a target at all.
			if len(relo.accessor) > 1 || relo.accessor[0] != 0 {
				return nil, fmt.Errorf("%s: unexpected accessor %v", relo.kind, relo.accessor)
			}

			result[uint64(relo.insnOff)] = COREFixup{
				relo.kind,
				uint32(relo.typeID),
				uint32(relo.typeID),
				false,
			}
			continue
		}

		relos, ok := relosByID[relo.typeID]
		if !ok {
			ids = append(ids, relo.typeID)
		}
		relosByID[relo.typeID] = append(relos, relo)
	}

	// Ensure we work on relocations in a deterministic order.
	sort.Slice(ids, func(i, j int) bool {
		return ids[i] < ids[j]
	})

	for _, id := range ids {
		if int(id) >= len(local.types) {
			return nil, fmt.Errorf("invalid type id %d", id)
		}

		localType := local.types[id]
		named, ok := localType.(namedType)
		if !ok || named.name() == "" {
			return nil, fmt.Errorf("relocate unnamed or anonymous type %s: %w", localType, ErrNotSupported)
		}

		relos := relosByID[id]
		targets := target.namedTypes[named.essentialName()]
		fixups, err := coreCalculateFixups(localType, targets, relos)
		if err != nil {
			return nil, fmt.Errorf("relocate %s: %w", localType, err)
		}

		for i, relo := range relos {
			result[uint64(relo.insnOff)] = fixups[i]
		}
	}

	return result, nil
}

var errAmbiguousRelocation = errors.New("ambiguous relocation")
var errImpossibleRelocation = errors.New("impossible relocation")

// coreCalculateFixups calculates the fixups for the given relocations using
// the "best" target.
//
// The best target is determined by scoring: the less poisoning we have to do
// the better the target is.
func coreCalculateFixups(local Type, targets []namedType, relos coreRelos) ([]COREFixup, error) {
	localID := local.ID()
	local, err := copyType(local, skipQualifierAndTypedef)
	if err != nil {
		return nil, err
	}

	bestScore := len(relos)
	var bestFixups []COREFixup
	for i := range targets {
		targetID := targets[i].ID()
		target, err := copyType(targets[i], skipQualifierAndTypedef)
		if err != nil {
			return nil, err
		}

		score := 0 // lower is better
		fixups := make([]COREFixup, 0, len(relos))
		for _, relo := range relos {
			fixup, err := coreCalculateFixup(local, localID, target, targetID, relo)
			if err != nil {
				return nil, fmt.Errorf("target %s: %w", target, err)
			}
			if fixup.Poison || fixup.isNonExistant() {
				score++
			}
			fixups = append(fixups, fixup)
		}

		if score > bestScore {
			// We have a better target already, ignore this one.
			continue
		}

		if score < bestScore {
			// This is the best target yet, use it.
			bestScore = score
			bestFixups = fixups
			continue
		}

		// Some other target has the same score as the current one. Make sure
		// the fixups agree with each other.
		for i, fixup := range bestFixups {
			if !fixup.equal(fixups[i]) {
				return nil, fmt.Errorf("%s: multiple types match: %w", fixup.Kind, errAmbiguousRelocation)
			}
		}
	}

	if bestFixups == nil {
		// Nothing at all matched, probably because there are no suitable
		// targets at all. Poison everything!
		bestFixups = make([]COREFixup, len(relos))
		for i, relo := range relos {
			bestFixups[i] = COREFixup{Kind: relo.kind, Poison: true}
		}
	}

	return bestFixups, nil
}

// coreCalculateFixup calculates the fixup for a single local type, target type
// and relocation.
func coreCalculateFixup(local Type, localID TypeID, target Type, targetID TypeID, relo coreRelo) (COREFixup, error) {
	fixup := func(local, target uint32) (COREFixup, error) {
		return COREFixup{relo.kind, local, target, false}, nil
	}
	poison := func() (COREFixup, error) {
		if relo.kind.checksForExistence() {
			return fixup(1, 0)
		}
		return COREFixup{relo.kind, 0, 0, true}, nil
	}
	zero := COREFixup{}

	switch relo.kind {
	case reloTypeIDTarget, reloTypeSize, reloTypeExists:
		if len(relo.accessor) > 1 || relo.accessor[0] != 0 {
			return zero, fmt.Errorf("%s: unexpected accessor %v", relo.kind, relo.accessor)
		}

		err := coreAreTypesCompatible(local, target)
		if errors.Is(err, errImpossibleRelocation) {
			return poison()
		}
		if err != nil {
			return zero, fmt.Errorf("relocation %s: %w", relo.kind, err)
		}

		switch relo.kind {
		case reloTypeExists:
			return fixup(1, 1)

		case reloTypeIDTarget:
			return fixup(uint32(localID), uint32(targetID))

		case reloTypeSize:
			localSize, err := Sizeof(local)
			if err != nil {
				return zero, err
			}

			targetSize, err := Sizeof(target)
			if err != nil {
				return zero, err
			}

			return fixup(uint32(localSize), uint32(targetSize))
		}

	case reloEnumvalValue, reloEnumvalExists:
		localValue, targetValue, err := coreFindEnumValue(local, relo.accessor, target)
		if errors.Is(err, errImpossibleRelocation) {
			return poison()
		}
		if err != nil {
			return zero, fmt.Errorf("relocation %s: %w", relo.kind, err)
		}

		switch relo.kind {
		case reloEnumvalExists:
			return fixup(1, 1)

		case reloEnumvalValue:
			return fixup(uint32(localValue.Value), uint32(targetValue.Value))
		}
	}

	return zero, fmt.Errorf("relocation %s: %w", relo.kind, ErrNotSupported)
}

/* coreAccessor contains a path through a struct. It contains at least one index.
 *
 * The interpretation depends on the kind of the relocation. The following is
 * taken from struct bpf_core_relo in libbpf_internal.h:
 *
 * - for field-based relocations, string encodes an accessed field using
 *   a sequence of field and array indices, separated by colon (:). It's
 *   conceptually very close to LLVM's getelementptr ([0]) instruction's
 *   arguments for identifying offset to a field.
 * - for type-based relocations, strings is expected to be just "0";
 * - for enum value-based relocations, string contains an index of enum
 *   value within its enum type;
 *
 * Example to provide a better feel.
 *
 *   struct sample {
 *       int a;
 *       struct {
 *           int b[10];
 *       };
 *   };
 *
 *   struct sample s = ...;
 *   int x = &s->a;     // encoded as "0:0" (a is field #0)
 *   int y = &s->b[5];  // encoded as "0:1:0:5" (anon struct is field #1,
 *                      // b is field #0 inside anon struct, accessing elem #5)
 *   int z = &s[10]->b; // encoded as "10:1" (ptr is used as an array)
 */
type coreAccessor []int

func parseCoreAccessor(accessor string) (coreAccessor, error) {
	if accessor == "" {
		return nil, fmt.Errorf("empty accessor")
	}

	var result coreAccessor
	parts := strings.Split(accessor, ":")
	for _, part := range parts {
		// 31 bits to avoid overflowing int on 32 bit platforms.
		index, err := strconv.ParseUint(part, 10, 31)
		if err != nil {
			return nil, fmt.Errorf("accessor index %q: %s", part, err)
		}

		result = append(result, int(index))
	}

	return result, nil
}

func (ca coreAccessor) String() string {
	strs := make([]string, 0, len(ca))
	for _, i := range ca {
		strs = append(strs, strconv.Itoa(i))
	}
	return strings.Join(strs, ":")
}

func (ca coreAccessor) enumValue(t Type) (*EnumValue, error) {
	e, ok := t.(*Enum)
	if !ok {
		return nil, fmt.Errorf("not an enum: %s", t)
	}

	if len(ca) > 1 {
		return nil, fmt.Errorf("invalid accessor %s for enum", ca)
	}

	i := ca[0]
	if i >= len(e.Values) {
		return nil, fmt.Errorf("invalid index %d for %s", i, e)
	}

	return &e.Values[i], nil
}

// coreFindEnumValue follows localAcc to find the equivalent enum value in target.
func coreFindEnumValue(local Type, localAcc coreAccessor, target Type) (localValue, targetValue *EnumValue, _ error) {
	localValue, err := localAcc.enumValue(local)
	if err != nil {
		return nil, nil, err
	}

	targetEnum, ok := target.(*Enum)
	if !ok {
		return nil, nil, errImpossibleRelocation
	}

	localName := localValue.Name.essentialName()
	for i, targetValue := range targetEnum.Values {
		if targetValue.Name.essentialName() != localName {
			continue
		}

		return localValue, &targetEnum.Values[i], nil
	}

	return nil, nil, errImpossibleRelocation
}

/* The comment below is from bpf_core_types_are_compat in libbpf.c:
 *
 * Check local and target types for compatibility. This check is used for
 * type-based CO-RE relocations and follow slightly different rules than
 * field-based relocations. This function assumes that root types were already
 * checked for name match. Beyond that initial root-level name check, names
 * are completely ignored. Compatibility rules are as follows:
 *   - any two STRUCTs/UNIONs/FWDs/ENUMs/INTs are considered compatible, but
 *     kind should match for local and target types (i.e., STRUCT is not
 *     compatible with UNION);
 *   - for ENUMs, the size is ignored;
 *   - for INT, size and signedness are ignored;
 *   - for ARRAY, dimensionality is ignored, element types are checked for
 *     compatibility recursively;
 *   - CONST/VOLATILE/RESTRICT modifiers are ignored;
 *   - TYPEDEFs/PTRs are compatible if types they pointing to are compatible;
 *   - FUNC_PROTOs are compatible if they have compatible signature: same
 *     number of input args and compatible return and argument types.
 * These rules are not set in stone and probably will be adjusted as we get
 * more experience with using BPF CO-RE relocations.
 *
 * Returns errImpossibleRelocation if types are not compatible.
 */
func coreAreTypesCompatible(localType Type, targetType Type) error {
	var (
		localTs, targetTs typeDeque
		l, t              = &localType, &targetType
		depth             = 0
	)

	for ; l != nil && t != nil; l, t = localTs.shift(), targetTs.shift() {
		if depth >= maxTypeDepth {
			return errors.New("types are nested too deep")
		}

		localType = *l
		targetType = *t

		if reflect.TypeOf(localType) != reflect.TypeOf(targetType) {
			return fmt.Errorf("type mismatch: %w", errImpossibleRelocation)
		}

		switch lv := (localType).(type) {
		case *Void, *Struct, *Union, *Enum, *Fwd:
			// Nothing to do here

		case *Int:
			tv := targetType.(*Int)
			if lv.isBitfield() || tv.isBitfield() {
				return fmt.Errorf("bitfield: %w", errImpossibleRelocation)
			}

		case *Pointer, *Array:
			depth++
			localType.walk(&localTs)
			targetType.walk(&targetTs)

		case *FuncProto:
			tv := targetType.(*FuncProto)
			if len(lv.Params) != len(tv.Params) {
				return fmt.Errorf("function param mismatch: %w", errImpossibleRelocation)
			}

			depth++
			localType.walk(&localTs)
			targetType.walk(&targetTs)

		default:
			return fmt.Errorf("unsupported type %T", localType)
		}
	}

	if l != nil {
		return fmt.Errorf("dangling local type %T", *l)
	}

	if t != nil {
		return fmt.Errorf("dangling target type %T", *t)
	}

	return nil
}

/* The comment below is from bpf_core_fields_are_compat in libbpf.c:
 *
 * Check two types for compatibility for the purpose of field access
 * relocation. const/volatile/restrict and typedefs are skipped to ensure we
 * are relocating semantically compatible entities:
 *   - any two STRUCTs/UNIONs are compatible and can be mixed;
 *   - any two FWDs are compatible, if their names match (modulo flavor suffix);
 *   - any two PTRs are always compatible;
 *   - for ENUMs, names should be the same (ignoring flavor suffix) or at
 *     least one of enums should be anonymous;
 *   - for ENUMs, check sizes, names are ignored;
 *   - for INT, size and signedness are ignored;
 *   - for ARRAY, dimensionality is ignored, element types are checked for
 *     compatibility recursively;
 *   - everything else shouldn't be ever a target of relocation.
 * These rules are not set in stone and probably will be adjusted as we get
 * more experience with using BPF CO-RE relocations.
 *
 * Returns errImpossibleRelocation if the members are not compatible.
 */
func coreAreMembersCompatible(localType Type, targetType Type) error {
	doNamesMatch := func(a, b string) error {
		if a == "" || b == "" {
			// allow anonymous and named type to match
			return nil
		}

		if essentialName(a) == essentialName(b) {
			return nil
		}

		return fmt.Errorf("names don't match: %w", errImpossibleRelocation)
	}

	for depth := 0; depth <= maxTypeDepth; depth++ {
		_, lok := localType.(composite)
		_, tok := targetType.(composite)
		if lok && tok {
			return nil
		}

		if reflect.TypeOf(localType) != reflect.TypeOf(targetType) {
			return fmt.Errorf("type mismatch: %w", errImpossibleRelocation)
		}

		switch lv := localType.(type) {
		case *Pointer:
			return nil

		case *Enum:
			tv := targetType.(*Enum)
			return doNamesMatch(lv.name(), tv.name())

		case *Fwd:
			tv := targetType.(*Fwd)
			return doNamesMatch(lv.name(), tv.name())

		case *Int:
			tv := targetType.(*Int)
			if lv.isBitfield() || tv.isBitfield() {
				return fmt.Errorf("bitfield: %w", errImpossibleRelocation)
			}
			return nil

		case *Array:
			tv := targetType.(*Array)

			localType = lv.Type
			targetType = tv.Type

		default:
			return fmt.Errorf("unsupported type %T", localType)
		}
	}

	return errors.New("types are nested too deep")
}

func skipQualifierAndTypedef(typ Type) (Type, error) {
	result := typ
	for depth := 0; depth <= maxTypeDepth; depth++ {
		switch v := (result).(type) {
		case qualifier:
			result = v.qualify()
		case *Typedef:
			result = v.Type
		default:
			return result, nil
		}
	}
	return nil, errors.New("exceeded type depth")
}
