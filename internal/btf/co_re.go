package btf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/cilium/ebpf/internal"
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
func (s *Spec) LoadCORERelocations(name string, targetBtf *Spec, bo binary.ByteOrder) (map[uint64]CORERelocation, error) {
	relos, ok := s.reloInfos[name]
	if !ok || len(relos.records) == 0 {
		return nil, nil
	}

	rs := map[uint64]CORERelocation{}
	cache := map[Type][]Type{}
	var err error

	if targetBtf == nil {
		targetBtf, err = LoadKernelSpec()
		if err != nil {
			return nil, fmt.Errorf("failed to get target btf: %w", err)
		}
	}

	for _, r := range relos.records {
		cr := coreReloRecord{}
		if err := binary.Read(bytes.NewReader(r.Opaque), bo, &cr); err != nil {
			return nil, fmt.Errorf("unable to read CO-RE relocation record: %w", err)
		}

		relo := CORERelocation{
			Type: s.indexedTypes[cr.TypeId],
			Kind: cr.ReloKind,
		}
		relo.Accessor, err = s.strings.Lookup(cr.AccessStrOff)
		if err != nil {
			return nil, fmt.Errorf("invalid CO-RE relocation accessor string: %w", err)
		}
		relo.Result, err = calculateRelocation(&relo, targetBtf, cache)
		if err != nil {
			return nil, fmt.Errorf("failed to calculate CO-RE relocation: %w", err)
		}

		rs[r.InsnOff] = relo
	}
	return rs, nil
}

func calculateRelocation(relo *CORERelocation, targetBtf *Spec, candCache map[Type][]Type) (*COREReloResult, error) {
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

	targetRes := &COREReloResult{}
	var targetSpec *coreSpec
	// TYPE_ID_LOCAL relo is special and doesn't need candidate search
	if relo.Kind == reloTypeIDLocal {
		targetRes = &COREReloResult{
			Validate: true,
			OrigVal:  uint32(localSpec.rootType.ID()),
			NewVal:   uint32(localSpec.rootType.ID()),
		}
		return targetRes, nil
	}

	if relo.Accessor == "" {
		return nil, fmt.Errorf("relocation doesn't support anonymous types")
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
			continue
		}
		candRes, err := coreCalculateRelocation(relo, localSpec, candSpec)
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
		targetRes, err = coreCalculateRelocation(relo, localSpec, nil)
		if err != nil {
			return nil, err
		}
	}

	return targetRes, nil
}

func coreParseSpec(typ Type, spec string, kind COREReloKind) (*coreSpec, error) {
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
	if len(rawIndexes) == 0 {
		return nil, ErrInvalidCORESpec
	}
	coreSpec.rawSpec = make([]uint32, len(rawIndexes))
	for i, s := range rawIndexes {
		idx, err := strconv.Atoi(s)
		if err != nil {
			return nil, fmt.Errorf("invalid spec index %s: %w", s, err)
		}
		coreSpec.rawSpec[i] = uint32(idx)
	}

	t := skipModsAndTypedefs(typ)

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
	coreSpec.bitOffset = accessIdx * uint32(sz) * 8

	for i := 1; i < len(coreSpec.rawSpec); i++ {
		t = skipModsAndTypedefs(t)
		accessIdx = coreSpec.rawSpec[i]

		if v, ok := t.(composite); ok {
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
		} else if a, ok := t.(*Array); ok {
			t = skipModsAndTypedefs(a)
			flex := isFlexArray(coreSpec.spec[len(coreSpec.spec)-1], a)
			if !flex && accessIdx >= a.Nelems {
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
		} else {
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

func coreCalculateRelocation(relo *CORERelocation, localSpec, targetSpec *coreSpec) (*COREReloResult, error) {
	res := &COREReloResult{Validate: true}
	err := errUnsupportedRelocation

	if relo.Kind.isFieldBased() {
		var validate *bool
		res.OrigVal, validate, err = coreCalculateFieldRelocation(relo, localSpec)
		if validate != nil {
			res.Validate = *validate
		}

		if err == nil {
			res.NewVal, _, err = coreCalculateFieldRelocation(relo, targetSpec)
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
	} else if err != nil {
		if errors.Is(err, errUnsupportedRelocation) {
			return nil, fmt.Errorf("unrecognized CO-RE relocation %s (%d)", relo.Kind, relo.Kind)
		}
		return nil, err
	}

	return res, nil
}

func coreCalculateTypeRelocation(relo *CORERelocation, spec *coreSpec) (uint32, error) {
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

func coreCalculateEnumvalRelocation(relo *CORERelocation, spec *coreSpec) (uint32, error) {
	switch relo.Kind {
	case reloEnumvalExists:
		if spec != nil {
			return 1, nil
		} else {
			return 0, nil
		}
	case reloEnumvalValue:
		if spec == nil {
			return 0, errStructureNeedsCleaning
		}
		acc := spec.spec[0]
		t := acc.typ
		et, ok := t.(*Enum)
		if !ok {
			return 0, fmt.Errorf("enumval relocation against non-enum type")
		}
		return uint32(et.Values[acc.idx].Value), nil
	default:
		return 0, errUnsupportedRelocation
	}
}

func coreCalculateFieldRelocation(relo *CORERelocation, spec *coreSpec) (uint32, *bool, error) {
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

	if acc.name == "" {
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
	mt := skipModsAndTypedefs(m.Type)
	bitOffset := spec.bitOffset
	bitSize := m.BitfieldSize
	var byteSize uint32
	var byteOffset uint32

	bitfield := bitSize > 0
	if bitfield {
		if ms, ok := mt.(sizer); ok {
			byteSize = ms.size()
			byteOff := bitOffset / 8 / byteSize * byteSize
			for (bitOffset + bitSize - byteOff*8) > (byteSize * 8) {
				if byteSize >= 8 {
					return 0, nil, fmt.Errorf("cannot be satisfied for bitfield")
				}
				byteSize *= 2
				byteOff = bitOffset / 8 / byteSize * byteSize
			}
		} else {
			return 0, nil, fmt.Errorf("bit offset was non-zero for a non-sizeable type")
		}
	} else {
		sz, err := Sizeof(m.Type)
		if err != nil {
			return 0, nil, err
		}
		byteSize = uint32(sz)
		byteOffset = spec.bitOffset / 8
		bitSize = byteSize / 8
	}

	validate = !bitfield

	switch relo.Kind {
	case reloFieldByteOffset:
		val = byteOffset
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
		if internal.NativeEndian == binary.LittleEndian {
			val = 64 - (bitOffset + bitSize - byteOffset*8)
		} else {
			val = (8-byteSize)*8 + (bitOffset - byteOffset*8)
		}
	case reloFieldRShiftU64:
		val = 64 - bitSize
		validate = true
	default:
		return 0, nil, errUnsupportedRelocation
	}

	return val, &validate, nil
}

func skipModsAndTypedefs(t Type) Type {
	for {
		switch v := t.(type) {
		case *Volatile:
			t = v.Type
		case *Const:
			t = v.Type
		case *Restrict:
			t = v.Type
		case *Typedef:
			t = v.Type
		default:
			return t
		}
	}
}

func isFlexArray(acc *coreAccessor, arr *Array) bool {
	// not a flexible array, if not inside a struct or has non-zero size
	if acc.name == "" || arr.Nelems > 0 {
		return false
	}

	if v, ok := acc.typ.(composite); ok {
		return acc.idx == uint32(len(v.members())-1)
	}
	return false
}

func (cs *coreSpec) Matches(targetType Type) (*coreSpec, error) {
	targetSpec := &coreSpec{
		rootType: targetType,
		reloKind: cs.reloKind,
	}

	if cs.reloKind.isTypeBased() {
		if compat, err := areTypesCompatible(cs.rootType, targetType); !compat || err != nil {
			return nil, err
		}
		return targetSpec, nil
	}

	localAcc := cs.spec[0]

	if cs.reloKind.isEnumValBased() {
		targetType = skipModsAndTypedefs(targetType)
		te, ok := targetType.(*Enum)
		if !ok {
			return nil, nil
		}

		localEssenName := localAcc.name.essentialName()
		for i, tev := range te.Values {
			if tev.essentialName() == localEssenName {
				targetSpec.spec = append(targetSpec.spec, &coreAccessor{
					typ:  targetType,
					idx:  uint32(i),
					name: tev.Name,
				})
				targetSpec.rawSpec = append(targetSpec.rawSpec, uint32(i))
				return targetSpec, nil
			}
		}

	}

	if !cs.reloKind.isFieldBased() {
		return nil, ErrInvalidCORESpec
	}

	for i, lacc := range cs.spec {
		targetType = skipModsAndTypedefs(targetType)

		if lacc.name != "" {
			matchedType, err := matchMember(lacc, targetType, targetSpec)
			if matchedType == nil || err != nil {
				return nil, err
			}
			targetType = matchedType
		} else {
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
				targetType = skipModsAndTypedefs(a.Type)
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
	}

	return targetSpec, nil
}

func areTypesCompatible(localType Type, targetType Type) (bool, error) {
	if reflect.TypeOf(localType) != reflect.TypeOf(targetType) {
		return false, nil
	}

	for depth := 32; depth >= 0; depth-- {
		localType = skipModsAndTypedefs(localType)
		targetType = skipModsAndTypedefs(targetType)
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
				lpType := skipModsAndTypedefs(p.Type)
				tpType := skipModsAndTypedefs(tp.Type)
				if compat, err := areTypesCompatible(lpType, tpType); !compat || err != nil {
					return false, err
				}
			}

			// tail recurse for return type check
			localType = skipModsAndTypedefs(v.Return)
			targetType = skipModsAndTypedefs(tv.Return)
			continue
		default:
			return false, nil
		}
	}

	return false, nil
}

func areFieldsCompatible(localType Type, targetType Type) (bool, error) {
	for {
		localType = skipModsAndTypedefs(localType)
		targetType = skipModsAndTypedefs(targetType)

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
			matches := localEssenName == "" || targetEssenName == "" || localEssenName == targetEssenName
			return matches, nil
		case *Fwd:
			tv := targetType.(*Fwd)
			localEssenName := v.essentialName()
			targetEssenName := tv.essentialName()
			matches := localEssenName == "" || targetEssenName == "" || localEssenName == targetEssenName
			return matches, nil
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
}

func matchMember(localAcc *coreAccessor, typ Type, targetSpec *coreSpec) (Type, error) {
	targetType := skipModsAndTypedefs(typ)
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
			compat, err := areFieldsCompatible(localMember.Type, tm.Type)
			if err != nil {
				return nil, err
			}
			if compat {
				targetAcc := &coreAccessor{
					typ:  typ,
					idx:  uint32(i),
					name: tm.Name,
				}
				targetSpec.spec = append(targetSpec.spec, targetAcc)
				return tm.Type, nil
			}
			return nil, nil
		}
		// turns out member wasn't correct
		targetSpec.bitOffset -= bitOffset
		targetSpec.rawSpec = targetSpec.rawSpec[:len(targetSpec.rawSpec)-1]
	}

	return nil, nil
}
