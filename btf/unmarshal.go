package btf

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"slices"
)

// readAndInflateTypes reads the raw btf type info and turns it into a graph
// of Types connected via pointers.
//
// If base is provided, then the types are considered to be of a split BTF
// (e.g., a kernel module).
//
// Returns a slice of types indexed by TypeID. Since BTF ignores compilation
// units, multiple types may share the same name. A Type may form a cyclic graph
// by pointing at itself.
func readAndInflateTypes(raw []byte, bo binary.ByteOrder, typeLen uint32, rawStrings *stringTable, base *Spec) ([]Type, error) {
	// because of the interleaving between types and struct members it is difficult to
	// precompute the numbers of raw types this will parse
	// this "guess" is a good first estimation
	sizeOfbtfType := uintptr(btfTypeLen)
	tyMaxCount := uintptr(typeLen) / sizeOfbtfType / 2
	types := make([]Type, 0, tyMaxCount)

	// Void is defined to always be type ID 0, and is thus omitted from BTF.
	types = append(types, (*Void)(nil))

	firstTypeID := TypeID(0)
	if base != nil {
		var err error
		firstTypeID, err = base.nextTypeID()
		if err != nil {
			return nil, err
		}

		// Split BTF doesn't contain Void.
		types = types[:0]
	}

	type fixupDef struct {
		id  TypeID
		typ *Type
	}

	var fixups []fixupDef
	fixup := func(id TypeID, typ *Type) {
		if id < firstTypeID {
			if baseType, err := base.TypeByID(id); err == nil {
				*typ = baseType
				return
			}
		}

		idx := int(id - firstTypeID)
		if idx < len(types) {
			// We've already inflated this type, fix it up immediately.
			*typ = types[idx]
			return
		}

		fixups = append(fixups, fixupDef{id, typ})
	}

	type bitfieldFixupDef struct {
		id TypeID
		m  *Member
	}

	var (
		legacyBitfields = make(map[TypeID][2]Bits) // offset, size
		bitfieldFixups  []bitfieldFixupDef
	)
	convertMembers := func(raw []btfMember, kindFlag bool) ([]Member, error) {
		// NB: The fixup below relies on pre-allocating this array to
		// work, since otherwise append might re-allocate members.
		members := make([]Member, 0, len(raw))
		for i, btfMember := range raw {
			name, err := rawStrings.Lookup(btfMember.NameOff)
			if err != nil {
				return nil, fmt.Errorf("can't get name for member %d: %w", i, err)
			}

			members = append(members, Member{
				Name:   name,
				Offset: Bits(btfMember.Offset),
			})

			m := &members[i]
			fixup(raw[i].Type, &m.Type)

			if kindFlag {
				m.BitfieldSize = Bits(btfMember.Offset >> 24)
				m.Offset &= 0xffffff
				// We ignore legacy bitfield definitions if the current composite
				// is a new-style bitfield. This is kind of safe since offset and
				// size on the type of the member must be zero if kindFlat is set
				// according to spec.
				continue
			}

			// This may be a legacy bitfield, try to fix it up.
			data, ok := legacyBitfields[raw[i].Type]
			if ok {
				// Bingo!
				m.Offset += data[0]
				m.BitfieldSize = data[1]
				continue
			}

			if m.Type != nil {
				// We couldn't find a legacy bitfield, but we know that the member's
				// type has already been inflated. Hence we know that it can't be
				// a legacy bitfield and there is nothing left to do.
				continue
			}

			// We don't have fixup data, and the type we're pointing
			// at hasn't been inflated yet. No choice but to defer
			// the fixup.
			bitfieldFixups = append(bitfieldFixups, bitfieldFixupDef{
				raw[i].Type,
				m,
			})
		}
		return members, nil
	}

	var (
		header    btfType
		bInt      btfInt
		bArr      btfArray
		bMembers  []btfMember
		bEnums    []btfEnum
		bParams   []btfParam
		bVariable btfVariable
		bSecInfos []btfVarSecinfo
		bDeclTag  btfDeclTag
		bEnums64  []btfEnum64
	)

	var declTags []*declTag
	for pos := raw; len(pos) > 0; {
		var (
			id  = firstTypeID + TypeID(len(types))
			typ Type
		)

		if len(pos) < btfTypeLen {
			return nil, fmt.Errorf("can't read type info for id %v: %v", id, io.ErrUnexpectedEOF)
		}

		if _, err := unmarshalBtfType(&header, pos[:btfTypeLen], bo); err != nil {
			return nil, fmt.Errorf("can't unmarshal type info for id %v: %v", id, err)
		}

		if id < firstTypeID {
			return nil, fmt.Errorf("no more type IDs")
		}

		name, err := rawStrings.Lookup(header.NameOff)
		if err != nil {
			return nil, fmt.Errorf("get name for type id %d: %w", id, err)
		}

		pos = pos[btfTypeLen:]

		switch header.Kind() {
		case kindInt:
			size := header.Size()
			if n, err := unmarshalBtfInt(&bInt, pos, bo); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfInt, id: %d: %w", id, err)
			} else {
				pos = pos[n:]
			}
			if bInt.Offset() > 0 || bInt.Bits().Bytes() != size {
				legacyBitfields[id] = [2]Bits{bInt.Offset(), bInt.Bits()}
			}
			typ = &Int{name, header.Size(), bInt.Encoding()}

		case kindPointer:
			ptr := &Pointer{nil}
			fixup(header.Type(), &ptr.Target)
			typ = ptr

		case kindArray:
			if n, err := unmarshalBtfArray(&bArr, pos, bo); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfArray, id: %d: %w", id, err)
			} else {
				pos = pos[n:]
			}

			arr := &Array{nil, nil, bArr.Nelems}
			fixup(bArr.IndexType, &arr.Index)
			fixup(bArr.Type, &arr.Type)
			typ = arr

		case kindStruct:
			vlen := header.Vlen()
			bMembers = slices.Grow(bMembers[:0], vlen)[:vlen]
			if n, err := unmarshalBtfMembers(bMembers, pos, bo); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfMembers, id: %d: %w", id, err)
			} else {
				pos = pos[n:]
			}

			members, err := convertMembers(bMembers, header.Bitfield())
			if err != nil {
				return nil, fmt.Errorf("struct %s (id %d): %w", name, id, err)
			}
			typ = &Struct{name, header.Size(), members, nil}

		case kindUnion:
			vlen := header.Vlen()
			bMembers = slices.Grow(bMembers[:0], vlen)[:vlen]
			if n, err := unmarshalBtfMembers(bMembers, pos, bo); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfMembers, id: %d: %w", id, err)
			} else {
				pos = pos[n:]
			}

			members, err := convertMembers(bMembers, header.Bitfield())
			if err != nil {
				return nil, fmt.Errorf("union %s (id %d): %w", name, id, err)
			}
			typ = &Union{name, header.Size(), members, nil}

		case kindEnum:
			vlen := header.Vlen()
			bEnums = slices.Grow(bEnums[:0], vlen)[:vlen]
			if n, err := unmarshalBtfEnums(bEnums, pos, bo); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfEnums, id: %d: %w", id, err)
			} else {
				pos = pos[n:]
			}

			vals := make([]EnumValue, 0, vlen)
			signed := header.Signed()
			for i, btfVal := range bEnums {
				name, err := rawStrings.Lookup(btfVal.NameOff)
				if err != nil {
					return nil, fmt.Errorf("get name for enum value %d: %s", i, err)
				}
				value := uint64(btfVal.Val)
				if signed {
					// Sign extend values to 64 bit.
					value = uint64(int32(btfVal.Val))
				}
				vals = append(vals, EnumValue{name, value})
			}
			typ = &Enum{name, header.Size(), signed, vals}

		case kindForward:
			typ = &Fwd{name, header.FwdKind()}

		case kindTypedef:
			typedef := &Typedef{name, nil, nil}
			fixup(header.Type(), &typedef.Type)
			typ = typedef

		case kindVolatile:
			volatile := &Volatile{nil}
			fixup(header.Type(), &volatile.Type)
			typ = volatile

		case kindConst:
			cnst := &Const{nil}
			fixup(header.Type(), &cnst.Type)
			typ = cnst

		case kindRestrict:
			restrict := &Restrict{nil}
			fixup(header.Type(), &restrict.Type)
			typ = restrict

		case kindFunc:
			fn := &Func{name, nil, header.Linkage(), nil, nil}
			fixup(header.Type(), &fn.Type)
			typ = fn

		case kindFuncProto:
			vlen := header.Vlen()
			bParams = slices.Grow(bParams[:0], vlen)[:vlen]
			if n, err := unmarshalBtfParams(bParams, pos, bo); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfParams, id: %d: %w", id, err)
			} else {
				pos = pos[n:]
			}

			params := make([]FuncParam, 0, vlen)
			for i, param := range bParams {
				name, err := rawStrings.Lookup(param.NameOff)
				if err != nil {
					return nil, fmt.Errorf("get name for func proto parameter %d: %s", i, err)
				}
				params = append(params, FuncParam{
					Name: name,
				})
			}
			for i := range params {
				fixup(bParams[i].Type, &params[i].Type)
			}

			fp := &FuncProto{nil, params}
			fixup(header.Type(), &fp.Return)
			typ = fp

		case kindVar:
			if n, err := unmarshalBtfVariable(&bVariable, pos, bo); err != nil {
				return nil, fmt.Errorf("can't read btfVariable, id: %d: %w", id, err)
			} else {
				pos = pos[n:]
			}

			v := &Var{name, nil, VarLinkage(bVariable.Linkage), nil}
			fixup(header.Type(), &v.Type)
			typ = v

		case kindDatasec:
			vlen := header.Vlen()
			bSecInfos = slices.Grow(bSecInfos[:0], vlen)[:vlen]
			if n, err := unmarshalBtfVarSecInfos(bSecInfos, pos, bo); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfVarSecInfos, id: %d: %w", id, err)
			} else {
				pos = pos[n:]
			}

			vars := make([]VarSecinfo, 0, vlen)
			for _, btfVar := range bSecInfos {
				vars = append(vars, VarSecinfo{
					Offset: btfVar.Offset,
					Size:   btfVar.Size,
				})
			}
			for i := range vars {
				fixup(bSecInfos[i].Type, &vars[i].Type)
			}
			typ = &Datasec{name, header.Size(), vars}

		case kindFloat:
			typ = &Float{name, header.Size()}

		case kindDeclTag:
			if n, err := unmarshalBtfDeclTag(&bDeclTag, pos, bo); err != nil {
				return nil, fmt.Errorf("can't read btfDeclTag, id: %d: %w", id, err)
			} else {
				pos = pos[n:]
			}

			btfIndex := bDeclTag.ComponentIdx
			if uint64(btfIndex) > math.MaxInt {
				return nil, fmt.Errorf("type id %d: index exceeds int", id)
			}

			dt := &declTag{nil, name, int(int32(btfIndex))}
			fixup(header.Type(), &dt.Type)
			typ = dt

			declTags = append(declTags, dt)

		case kindTypeTag:
			tt := &TypeTag{nil, name}
			fixup(header.Type(), &tt.Type)
			typ = tt

		case kindEnum64:
			vlen := header.Vlen()
			bEnums64 = slices.Grow(bEnums64[:0], vlen)[:vlen]
			if n, err := unmarshalBtfEnums64(bEnums64, pos, bo); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfEnum64s, id: %d: %w", id, err)
			} else {
				pos = pos[n:]
			}

			vals := make([]EnumValue, 0, vlen)
			for i, btfVal := range bEnums64 {
				name, err := rawStrings.Lookup(btfVal.NameOff)
				if err != nil {
					return nil, fmt.Errorf("get name for enum64 value %d: %s", i, err)
				}
				value := (uint64(btfVal.ValHi32) << 32) | uint64(btfVal.ValLo32)
				vals = append(vals, EnumValue{name, value})
			}
			typ = &Enum{name, header.Size(), header.Signed(), vals}

		default:
			return nil, fmt.Errorf("type id %d: unknown kind: %v", id, header.Kind())
		}

		types = append(types, typ)
	}

	for _, fixup := range fixups {
		if fixup.id < firstTypeID {
			return nil, fmt.Errorf("fixup for base type id %d is not expected", fixup.id)
		}

		idx := int(fixup.id - firstTypeID)
		if idx >= len(types) {
			return nil, fmt.Errorf("reference to invalid type id: %d", fixup.id)
		}

		*fixup.typ = types[idx]
	}

	for _, bitfieldFixup := range bitfieldFixups {
		if bitfieldFixup.id < firstTypeID {
			return nil, fmt.Errorf("bitfield fixup from split to base types is not expected")
		}

		data, ok := legacyBitfields[bitfieldFixup.id]
		if ok {
			// This is indeed a legacy bitfield, fix it up.
			bitfieldFixup.m.Offset += data[0]
			bitfieldFixup.m.BitfieldSize = data[1]
		}
	}

	for _, dt := range declTags {
		switch t := dt.Type.(type) {
		case *Var:
			if dt.Index != -1 {
				return nil, fmt.Errorf("type %s: component idx %d is not -1", dt, dt.Index)
			}
			t.Tags = append(t.Tags, dt.Value)

		case *Typedef:
			if dt.Index != -1 {
				return nil, fmt.Errorf("type %s: component idx %d is not -1", dt, dt.Index)
			}
			t.Tags = append(t.Tags, dt.Value)

		case composite:
			if dt.Index >= 0 {
				members := t.members()
				if dt.Index >= len(members) {
					return nil, fmt.Errorf("type %s: component idx %d exceeds members of %s", dt, dt.Index, t)
				}

				members[dt.Index].Tags = append(members[dt.Index].Tags, dt.Value)
				continue
			}

			if dt.Index == -1 {
				switch t2 := t.(type) {
				case *Struct:
					t2.Tags = append(t2.Tags, dt.Value)
				case *Union:
					t2.Tags = append(t2.Tags, dt.Value)
				}

				continue
			}

			return nil, fmt.Errorf("type %s: decl tag for type %s has invalid component idx", dt, t)

		case *Func:
			fp, ok := t.Type.(*FuncProto)
			if !ok {
				return nil, fmt.Errorf("type %s: %s is not a FuncProto", dt, t.Type)
			}

			// Ensure the number of argument tag lists equals the number of arguments
			if len(t.ParamTags) == 0 {
				t.ParamTags = make([][]string, len(fp.Params))
			}

			if dt.Index >= 0 {
				if dt.Index >= len(fp.Params) {
					return nil, fmt.Errorf("type %s: component idx %d exceeds params of %s", dt, dt.Index, t)
				}

				t.ParamTags[dt.Index] = append(t.ParamTags[dt.Index], dt.Value)
				continue
			}

			if dt.Index == -1 {
				t.Tags = append(t.Tags, dt.Value)
				continue
			}

			return nil, fmt.Errorf("type %s: decl tag for type %s has invalid component idx", dt, t)

		default:
			return nil, fmt.Errorf("type %s: decl tag for type %s is not supported", dt, t)
		}
	}

	return types, nil
}
