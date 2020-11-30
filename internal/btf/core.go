package btf

import (
	"errors"
	"fmt"
	"reflect"
)

// Code in this file is derived from libbpf, which is available under a BSD
// 2-Clause license.

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
 */
func coreAreTypesCompatible(localType Type, targetType Type) (bool, error) {
	var (
		localTs, targetTs typeDeque
		l, t              = &localType, &targetType
		depth             = 0
	)

	for ; l != nil && t != nil; l, t = localTs.shift(), targetTs.shift() {
		if depth >= maxTypeDepth {
			return false, errors.New("types are nested too deep")
		}

		localType = skipQualifierAndTypedef(*l)
		targetType = skipQualifierAndTypedef(*t)

		if reflect.TypeOf(localType) != reflect.TypeOf(targetType) {
			return false, nil
		}

		switch lv := (localType).(type) {
		case *Void, *Struct, *Union, *Enum, *Fwd:
			// Nothing to do here

		case *Int:
			tv := targetType.(*Int)
			if lv.isBitfield() || tv.isBitfield() {
				return false, nil
			}

		case *Pointer, *Array:
			depth++
			localType.walk(&localTs)
			targetType.walk(&targetTs)

		case *FuncProto:
			tv := targetType.(*FuncProto)
			if len(lv.Params) != len(tv.Params) {
				return false, nil
			}

			depth++
			localType.walk(&localTs)
			targetType.walk(&targetTs)

		default:
			return false, fmt.Errorf("unsupported type %T", localType)
		}
	}

	if l != nil {
		return false, fmt.Errorf("dangling local type %T", *l)
	}

	if t != nil {
		return false, fmt.Errorf("dangling target type %T", *t)
	}

	return true, nil
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
 */
func coreAreMembersCompatible(localType Type, targetType Type) (bool, error) {
	doNamesMatch := func(a, b string) bool {
		if a == "" || b == "" {
			// allow anonymous and named type to match
			return true
		}

		return essentialName(a) == essentialName(b)
	}

	for depth := 0; depth <= maxTypeDepth; depth++ {
		localType = skipQualifierAndTypedef(localType)
		targetType = skipQualifierAndTypedef(targetType)

		_, lok := localType.(composite)
		_, tok := targetType.(composite)
		if lok && tok {
			return true, nil
		}

		if reflect.TypeOf(localType) != reflect.TypeOf(targetType) {
			return false, nil
		}

		switch lv := localType.(type) {
		case *Pointer:
			return true, nil

		case *Enum:
			tv := targetType.(*Enum)
			return doNamesMatch(lv.name(), tv.name()), nil

		case *Fwd:
			tv := targetType.(*Fwd)
			return doNamesMatch(lv.name(), tv.name()), nil

		case *Int:
			tv := targetType.(*Int)
			return !lv.isBitfield() && !tv.isBitfield(), nil

		case *Array:
			tv := targetType.(*Array)

			localType = lv.Type
			targetType = tv.Type

		default:
			return false, fmt.Errorf("unsupported type %T", localType)
		}
	}

	return false, errors.New("types are nested too deep")
}

func skipQualifierAndTypedef(typ Type) Type {
	result := typ
	for depth := 0; depth <= maxTypeDepth; depth++ {
		switch v := (result).(type) {
		case qualifier:
			result = v.qualify()
		case *Typedef:
			result = v.Type
		default:
			return result
		}
	}
	return typ
}
