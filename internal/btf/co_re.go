package btf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

var (
	// ErrInvalidCORESpec indicates an invalid CO-RE relocation spec was parsed
	ErrInvalidCORESpec        = errors.New("invalid CO-RE spec")
	errStructureNeedsCleaning = errors.New("structure needs cleaning")
	errUnsupportedRelocation  = errors.New("unsupported CO-RE relocation")
)

// LoadCORERelocations parses the relocations from the BTF extended ELF section and calculates how to apply
// the relocation to the target, described by the BTF provided. If no BTF is provided, the current kernel BTF
// will attempted to be loaded. Returns a mapping between instruction offset and the relocation, with result.
func (s *Spec) LoadCORERelocations(name string, targetBtf *Spec) (map[uint64]*CORERelocation, error) {
	relos, ok := s.reloInfos[name]
	if !ok || len(relos) == 0 {
		return nil, nil
	}

	rs := map[uint64]*CORERelocation{}
	cache := map[Type][]Type{}
	var err error

	if targetBtf == nil {
		targetBtf, err = LoadKernelSpec()
		if err != nil {
			return nil, fmt.Errorf("failed to get target btf: %w", err)
		}
	}

	if s.byteOrder != targetBtf.byteOrder {
		return nil, fmt.Errorf("program and target byte order does not match")
	}

	for _, cr := range relos {
		relo := coreRelocationRecord{
			Type: s.indexedTypes[cr.TypeId],
			Kind: cr.ReloKind,
		}
		relo.Accessor, err = s.strings.Lookup(cr.AccessStrOff)
		if err != nil {
			return nil, fmt.Errorf("invalid CO-RE relocation accessor string: %w", err)
		}
		result, err := calculateRelocation(&relo, targetBtf, s.byteOrder, cache)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate CO-RE relocation: %w", err)
		}

		rs[cr.InsnOff] = result
	}
	return rs, nil
}

func calculateRelocation(relo *coreRelocationRecord, targetBtf *Spec, bo binary.ByteOrder, candCache map[Type][]Type) (*CORERelocation, error) {
	typ := relo.Type

	var localName string
	if n, ok := typ.(namer); ok {
		localName = n.name()
	}

	localSpec, err := coreParseSpec(typ, relo.Accessor, relo.Kind)
	if err != nil {
		if localName == "" {
			localName = "<anon>"
		}
		return nil, fmt.Errorf("parsing [%v] %T %s + %s failed: %w", typ, typ, localName, relo.Accessor, err)
	}

	targetRes := &CORERelocation{}
	var targetSpec *coreSpec
	// TYPE_ID_LOCAL relo is special and doesn't need candidate search
	if relo.Kind == reloTypeIDLocal {
		targetRes = &CORERelocation{
			Validate: true,
			OrigVal:  uint32(localSpec.rootType.ID()),
			NewVal:   uint32(localSpec.rootType.ID()),
		}
		return targetRes, nil
	}

	cands, ok := candCache[typ]
	if !ok {
		cands, err = findCandidates(typ, targetBtf)
		if err != nil {
			return nil, fmt.Errorf("target candidate search failed: %w", err)
		}
		candCache[typ] = cands
	}

	var matchingTypes []Type
	for _, cand := range cands {
		candSpec, err := localSpec.Matches(cand)
		if err != nil {
			return nil, fmt.Errorf("error matching candidate: %w", err)
		}
		if candSpec == nil {
			// candidate doesn't match, so keep searching
			continue
		}
		candRes, err := coreCalculateRelocation(relo, localSpec, candSpec, bo)
		if err != nil {
			return nil, err
		}

		if len(matchingTypes) == 0 {
			targetRes = candRes
			targetSpec = candSpec
		} else if targetSpec != nil && candSpec.bitOffset != targetSpec.bitOffset {
			return nil, fmt.Errorf("field offset ambiguity: %d != %d", candSpec.bitOffset, targetSpec.bitOffset)
		} else if candRes.Poison != targetRes.Poison || candRes.NewVal != targetRes.NewVal {
			return nil, fmt.Errorf("relocation decision ambiguity: success:%v %d != success:%v %d", candRes.Poison, candRes.NewVal, targetRes.Poison, targetRes.NewVal)
		}

		matchingTypes = append(matchingTypes, candSpec.rootType)
	}

	if len(matchingTypes) > 0 {
		candCache[typ] = matchingTypes
	}

	if len(matchingTypes) == 0 {
		targetRes, err = coreCalculateRelocation(relo, localSpec, nil, bo)
		if err != nil {
			return nil, err
		}
	}

	return targetRes, nil
}

func coreParseSpec(typ Type, spec string, kind coreReloKind) (*coreSpec, error) {
	if spec == "" || spec == ":" {
		return nil, ErrInvalidCORESpec
	}
	var err error
	coreSpec := coreSpec{
		rootType: typ,
		reloKind: kind,
	}

	if kind.isTypeBased() {
		if spec == "0" {
			return nil, ErrInvalidCORESpec
		}
		return &coreSpec, nil
	}

	rawIndexes := strings.SplitN(spec, ":", coreSpecMaxLen+1)
	if len(rawIndexes) > coreSpecMaxLen {
		return nil, fmt.Errorf("spec string too big")
	}
	coreSpec.rawSpec = make([]uint32, len(rawIndexes))
	for i, s := range rawIndexes {
		idx, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid spec index %s: %w", s, err)
		}
		coreSpec.rawSpec[i] = uint32(idx)
	}

	t, err := skipModsAndTypedefs(typ)
	if err != nil {
		return nil, err
	}

	accessIdx := coreSpec.rawSpec[0]
	acc := &coreAccessor{
		typ: t,
		idx: accessIdx,
	}
	coreSpec.spec = append(coreSpec.spec, acc)

	if kind.isEnumValBased() {
		e, ok := t.(*Enum)
		if !ok || len(coreSpec.rawSpec) > 1 || accessIdx >= uint32(len(e.Values)) {
			return nil, ErrInvalidCORESpec
		}
		acc.name = e.Values[accessIdx].Name
		return &coreSpec, nil
	}

	if !kind.isFieldBased() {
		return nil, ErrInvalidCORESpec
	}

	sz, err := Sizeof(t)
	if err != nil {
		return nil, fmt.Errorf("failed to get size of type %v: %w", t, err)
	}
	// calculate initial offset due to array-style indexed access (e.g. a[3] is 3 sizeof(a) offsets from start)
	coreSpec.bitOffset = accessIdx * uint32(sz) * 8

	for i := 1; i < len(coreSpec.rawSpec); i++ {
		t, err = skipModsAndTypedefs(t)
		if err != nil {
			return nil, err
		}
		accessIdx = coreSpec.rawSpec[i]

		switch v := t.(type) {
		case composite:
			if accessIdx >= uint32(len(v.members())) {
				return nil, fmt.Errorf("invalid array index")
			}
			m := v.members()[accessIdx]
			coreSpec.bitOffset += m.Offset
			if m.Name != "" {
				coreSpec.spec = append(coreSpec.spec, &coreAccessor{
					typ:  t,
					idx:  accessIdx,
					name: m.Name,
				})
			}
			t = m.Type
		case *Array:
			t, err = skipModsAndTypedefs(v.Type)
			if err != nil {
				return nil, err
			}
			flex := isFlexArray(coreSpec.spec[len(coreSpec.spec)-1], v)
			if !flex && accessIdx >= v.Nelems {
				return nil, fmt.Errorf("invalid array index")
			}

			coreSpec.spec = append(coreSpec.spec, &coreAccessor{
				typ: t,
				idx: accessIdx,
			})
			sz, err = Sizeof(t)
			if err != nil {
				return nil, fmt.Errorf("failed to get size of type %v: %w", t, err)
			}
			coreSpec.bitOffset += accessIdx * uint32(sz) * 8
		default:
			return nil, fmt.Errorf("relo for [%v] %s (at idx %d) captures type [%d] of unexpected kind %s", typ, spec, i, t.ID(), t)
		}
	}

	return &coreSpec, nil
}

func findCandidates(localType Type, targetBtf *Spec) ([]Type, error) {
	ln, ok := localType.(namer)
	if !ok || ln.name() == "" {
		return nil, fmt.Errorf("type %v must have a name", localType)
	}
	localEssenName := Name(ln.name()).essentialName()
	var cands []Type

	// index 0 is void
	for i := 1; i < len(targetBtf.indexedTypes); i++ {
		t := targetBtf.indexedTypes[i]
		if reflect.TypeOf(t) != reflect.TypeOf(localType) {
			continue
		}
		tn, ok := t.(namer)
		if !ok || tn.name() == "" {
			continue
		}
		if Name(tn.name()).essentialName() != localEssenName {
			continue
		}

		cands = append(cands, t)
	}

	return cands, nil
}

func coreCalculateRelocation(relo *coreRelocationRecord, localSpec, targetSpec *coreSpec, bo binary.ByteOrder) (*CORERelocation, error) {
	res := &CORERelocation{Validate: true}
	err := errUnsupportedRelocation

	if relo.Kind.isFieldBased() {
		var validate *bool
		res.OrigVal, validate, err = coreCalculateFieldRelocation(relo, localSpec, bo)
		if validate != nil {
			res.Validate = *validate
		}

		if err == nil {
			res.NewVal, _, err = coreCalculateFieldRelocation(relo, targetSpec, bo)
		}
	} else if relo.Kind.isTypeBased() {
		res.OrigVal, err = coreCalculateTypeRelocation(relo, localSpec)
		if err == nil {
			res.NewVal, err = coreCalculateTypeRelocation(relo, targetSpec)
		}
	} else if relo.Kind.isEnumValBased() {
		res.OrigVal, err = coreCalculateEnumvalRelocation(relo, localSpec)
		if err == nil {
			res.NewVal, err = coreCalculateEnumvalRelocation(relo, targetSpec)
		}
	}

	if errors.Is(err, errStructureNeedsCleaning) {
		res.Poison = true
	} else if errors.Is(err, errUnsupportedRelocation) {
		return nil, fmt.Errorf("unrecognized CO-RE relocation %s (%d)", relo.Kind, relo.Kind)
	} else if err != nil {
		return nil, err
	}

	return res, nil
}

func coreCalculateTypeRelocation(relo *coreRelocationRecord, spec *coreSpec) (uint32, error) {
	if spec == nil {
		return 0, nil
	}

	switch relo.Kind {
	case reloTypeIDTarget:
		return uint32(spec.rootType.ID()), nil
	case reloTypeExists:
		return 1, nil
	case reloTypeSize:
		sz, err := Sizeof(spec.rootType)
		if err != nil {
			return 0, err
		}
		return uint32(sz), nil
	default:
		return 0, errUnsupportedRelocation
	}
}

func coreCalculateEnumvalRelocation(relo *coreRelocationRecord, spec *coreSpec) (uint32, error) {
	switch relo.Kind {
	case reloEnumvalExists:
		if spec != nil {
			return 1, nil
		}
		return 0, nil
	case reloEnumvalValue:
		if spec == nil {
			return 0, errStructureNeedsCleaning
		}
		acc := spec.spec[0]
		et, ok := acc.typ.(*Enum)
		if !ok {
			return 0, fmt.Errorf("enumval relocation against non-enum type")
		}
		return uint32(et.Values[acc.idx].Value), nil
	default:
		return 0, errUnsupportedRelocation
	}
}

func coreCalculateFieldRelocation(relo *coreRelocationRecord, spec *coreSpec, bo binary.ByteOrder) (uint32, *bool, error) {
	var val uint32
	var validate bool

	if relo.Kind == reloFieldExists {
		if spec != nil {
			return 1, nil, nil
		} else {
			return 0, nil, nil
		}
	}

	if spec == nil {
		return 0, nil, errStructureNeedsCleaning
	}

	acc := spec.spec[len(spec.spec)-1]
	t := acc.typ

	if acc.isAnonymous() {
		if relo.Kind == reloFieldByteOffset {
			val = spec.bitOffset / 8
		} else if relo.Kind == reloFieldByteSize {
			sz, err := Sizeof(t)
			if err != nil {
				return 0, nil, err
			}
			val = uint32(sz)
		} else {
			return 0, nil, fmt.Errorf("relocation cannot be applied to array access")
		}
		validate = true
		return val, &validate, nil
	}

	ct, ok := t.(composite)
	if !ok {
		return 0, nil, fmt.Errorf("non-composite type for relocation: %T", t)
	}
	m := ct.members()[acc.idx]
	mt, err := skipModsAndTypedefs(m.Type)
	if err != nil {
		return 0, nil, err
	}
	bitOffset := spec.bitOffset
	bitfieldSize := m.BitfieldSize
	var byteSize uint32
	var byteOffset uint32

	bitfield := bitfieldSize > 0
	if bitfield {
		ms, ok := mt.(sizer)
		if !ok {
			return 0, nil, fmt.Errorf("bit offset was non-zero for a non-sizeable type")
		}
		byteSize = ms.size()
		byteOff := bitOffset / 8 / byteSize * byteSize
		// figure out smallest size for bitfield load
		for (bitOffset + bitfieldSize - byteOff*8) > (byteSize * 8) {
			if byteSize >= 8 {
				return 0, nil, fmt.Errorf("bitfield cannot be read with 64-bit read")
			}
			byteSize *= 2
			byteOff = bitOffset / 8 / byteSize * byteSize
		}
	} else {
		sz, err := Sizeof(m.Type)
		if err != nil {
			return 0, nil, err
		}
		byteSize = uint32(sz)
		byteOffset = bitOffset / 8
		bitfieldSize = byteSize * 8
	}

	validate = !bitfield

	switch relo.Kind {
	case reloFieldByteOffset:
		val = byteOffset
	// all remaining relocations are used specifically to support bitfield relocations.
	// the left and right shifts are used to isolate specific bits within a word
	// byte size is used to ensure the correct size of memory read
	// signed is to adjust to the signedness of the target bitfield
	// see https://github.com/libbpf/libbpf/commit/4438972ccc172ce2a68ee5d2ec2a01303aa380a8
	case reloFieldByteSize:
		val = byteSize
	case reloFieldSigned:
		switch v := mt.(type) {
		case *Enum:
			val = 1
		case *Int:
			if v.Encoding == Signed {
				val = 1
			} else {
				val = 0
			}
		default:
			val = 0
		}
		validate = true
	case reloFieldLShiftU64:
		if bo == binary.LittleEndian {
			val = 64 - (bitOffset + bitfieldSize - byteOffset*8)
		} else {
			val = (8-byteSize)*8 + (bitOffset - byteOffset*8)
		}
	case reloFieldRShiftU64:
		val = 64 - bitfieldSize
		validate = true
	default:
		return 0, nil, errUnsupportedRelocation
	}

	return val, &validate, nil
}

func isFlexArray(acc *coreAccessor, arr *Array) bool {
	// must be named and have zero size
	if acc.isAnonymous() || arr.Nelems > 0 {
		return false
	}
	// parent must be a struct
	s, parentIsStruct := acc.typ.(*Struct)
	if !parentIsStruct {
		return false
	}
	// must be last field in struct
	return acc.idx == uint32(len(s.Members)-1)
}

func (cs *coreSpec) Matches(targetType Type) (*coreSpec, error) {
	var err error
	targetSpec := &coreSpec{
		rootType: targetType,
		reloKind: cs.reloKind,
	}

	if cs.reloKind.isTypeBased() {
		if compat, err := coreAreTypesCompatible(cs.rootType, targetType); !compat || err != nil {
			return nil, err
		}
		return targetSpec, nil
	}

	localAcc := cs.spec[0]

	if cs.reloKind.isEnumValBased() {
		targetType, err = skipModsAndTypedefs(targetType)
		if err != nil {
			return nil, err
		}

		te, ok := targetType.(*Enum)
		if !ok {
			return nil, nil
		}

		localEssenName := localAcc.name.essentialName()
		for i, tev := range te.Values {
			if tev.essentialName() != localEssenName {
				continue
			}
			targetSpec.spec = []*coreAccessor{{
				typ:  targetType,
				idx:  uint32(i),
				name: tev.Name,
			}}
			targetSpec.rawSpec = []uint32{uint32(i)}
			return targetSpec, nil
		}
	}

	if !cs.reloKind.isFieldBased() {
		return nil, fmt.Errorf("%w: unknown relocation kind %#x", ErrInvalidCORESpec, cs.reloKind)
	}

	for i, lacc := range cs.spec {
		targetType, err = skipModsAndTypedefs(targetType)
		if err != nil {
			return nil, err
		}

		if !lacc.isAnonymous() {
			matchedType, err := matchMember(lacc, targetType, targetSpec)
			if matchedType == nil || err != nil {
				return nil, err
			}
			targetType = matchedType
			continue
		}

		// for i=0, target is treated as array type
		// for others we must find the array type
		if i > 0 {
			a, isArray := targetType.(*Array)
			if !isArray {
				return nil, nil
			}
			flex := isFlexArray(targetSpec.spec[i-1], a)
			if !flex && lacc.idx >= a.Nelems {
				return nil, nil
			}
			targetType, err = skipModsAndTypedefs(a.Type)
			if err != nil {
				return nil, err
			}
		}

		if len(targetSpec.rawSpec) >= coreSpecMaxLen {
			return nil, fmt.Errorf("struct/union/array nesting is too deep")
		}

		tacc := &coreAccessor{
			typ: targetType,
			idx: lacc.idx,
		}
		targetSpec.spec = append(targetSpec.spec, tacc)
		targetSpec.rawSpec = append(targetSpec.rawSpec, tacc.idx)

		sz, err := Sizeof(targetType)
		if err != nil {
			return nil, err
		}
		targetSpec.bitOffset += lacc.idx * uint32(sz) * 8
	}

	return targetSpec, nil
}

func coreAreTypesCompatible(localType Type, targetType Type) (bool, error) {
	if reflect.TypeOf(localType) != reflect.TypeOf(targetType) {
		return false, nil
	}

	var err error
	for depth := 0; depth <= maxTypeDepth; depth++ {
		localType, err = skipModsAndTypedefs(localType)
		if err != nil {
			return false, err
		}
		targetType, err = skipModsAndTypedefs(targetType)
		if err != nil {
			return false, err
		}

		if reflect.TypeOf(localType) != reflect.TypeOf(targetType) {
			return false, nil
		}

		switch v := localType.(type) {
		case *Struct, *Union, *Enum, *Fwd:
			return true, nil
		case *Int:
			tv := targetType.(*Int)
			return v.Offset == 0 && tv.Offset == 0, nil
		case *Pointer:
			tv := targetType.(*Pointer)
			localType = v.Target
			targetType = tv.Target
			continue
		case *Array:
			tv := targetType.(*Array)
			localType = v.Type
			targetType = tv.Type
			continue
		case *FuncProto:
			tv := targetType.(*FuncProto)
			if len(v.Params) != len(tv.Params) {
				return false, nil
			}

			for i, p := range v.Params {
				tp := tv.Params[i]
				lpType, err := skipModsAndTypedefs(p.Type)
				if err != nil {
					return false, err
				}
				tpType, err := skipModsAndTypedefs(tp.Type)
				if err != nil {
					return false, err
				}
				if compat, err := coreAreTypesCompatible(lpType, tpType); !compat || err != nil {
					return false, err
				}
			}

			// tail recurse for return type check
			localType, err = skipModsAndTypedefs(v.Return)
			if err != nil {
				return false, err
			}
			targetType, err = skipModsAndTypedefs(tv.Return)
			if err != nil {
				return false, err
			}
			continue
		default:
			return false, nil
		}
	}

	return false, errors.New("exceeded type depth")
}

func areMembersCompatible(localType Type, targetType Type) (bool, error) {
	var err error
	for depth := 0; depth <= maxTypeDepth; depth++ {
		localType, err = skipModsAndTypedefs(localType)
		if err != nil {
			return false, err
		}
		targetType, err = skipModsAndTypedefs(targetType)
		if err != nil {
			return false, err
		}

		_, lok := localType.(composite)
		_, tok := targetType.(composite)
		if lok && tok {
			return true, nil
		}
		if reflect.TypeOf(localType) != reflect.TypeOf(targetType) {
			return false, nil
		}

		switch v := localType.(type) {
		case *Pointer:
			return true, nil
		case *Enum:
			tv := targetType.(*Enum)
			localEssenName := v.essentialName()
			targetEssenName := tv.essentialName()
			// allow anonymous to named to match
			if localEssenName == "" || targetEssenName == "" {
				return true, nil
			}
			return localEssenName == targetEssenName, nil
		case *Fwd:
			tv := targetType.(*Fwd)
			localEssenName := v.essentialName()
			targetEssenName := tv.essentialName()
			// allow anonymous to named to match
			if localEssenName == "" || targetEssenName == "" {
				return true, nil
			}
			return localEssenName == targetEssenName, nil
		case *Int:
			tv := targetType.(*Int)
			return v.Offset == 0 && tv.Offset == 0, nil
		case *Array:
			tv := targetType.(*Array)
			localType = v.Type
			targetType = tv.Type
			continue
		default:
			return false, nil
		}
	}

	return false, errors.New("exceeded type depth")
}

func matchMember(localAcc *coreAccessor, typ Type, targetSpec *coreSpec) (Type, error) {
	targetType, err := skipModsAndTypedefs(typ)
	if err != nil {
		return nil, err
	}
	tc, ok := targetType.(composite)
	if !ok {
		return nil, nil
	}

	lc, ok := localAcc.typ.(composite)
	if !ok {
		return nil, nil
	}
	localMember := lc.members()[localAcc.idx]

	for i, tm := range tc.members() {
		bitOffset := tm.Offset
		if len(targetSpec.rawSpec) >= coreSpecMaxLen {
			return nil, fmt.Errorf("struct/union/array nesting is too deep")
		}
		// speculative addition
		targetSpec.bitOffset += bitOffset
		targetSpec.rawSpec = append(targetSpec.rawSpec, uint32(i))
		if tm.Name == "" {
			// embedded struct/union, go deeper
			foundType, err := matchMember(localAcc, tm.Type, targetSpec)
			if foundType != nil || err != nil {
				return foundType, err
			}
		} else if localMember.Name == tm.Name {
			compat, err := areMembersCompatible(localMember.Type, tm.Type)
			if err != nil {
				return nil, err
			}
			if !compat {
				return nil, nil
			}

			targetAcc := &coreAccessor{
				typ:  typ,
				idx:  uint32(i),
				name: tm.Name,
			}
			targetSpec.spec = append(targetSpec.spec, targetAcc)
			return tm.Type, nil
		}
		// turns out member wasn't correct
		targetSpec.bitOffset -= bitOffset
		targetSpec.rawSpec = targetSpec.rawSpec[:len(targetSpec.rawSpec)-1]
	}

	return nil, nil
}
