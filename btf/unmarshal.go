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
func readAndInflateTypes(raw []byte, bo binary.ByteOrder, _ uint32, rawStrings *stringTable, base *Spec) ([]Type, error) {
	d, err := newDecoder(raw, bo, rawStrings, base)
	if err != nil {
		return nil, err
	}
	return d.inflateAll()
}

type decoder struct {
	// Immutable fields, may be shared.

	base        *Spec
	byteOrder   binary.ByteOrder
	raw         []byte
	strings     *stringTable
	firstTypeID TypeID
	offsets     []int // map[TypeID]int
	declTags    map[TypeID][]TypeID

	// Mutable fields, must be copied.

	types           map[TypeID]Type
	legacyBitfields map[TypeID][2]Bits // offset, size
}

func newDecoder(raw []byte, bo binary.ByteOrder, strings *stringTable, base *Spec) (*decoder, error) {
	var offsets []int
	firstTypeID := TypeID(0)
	id := TypeID(1)
	if base != nil {
		var err error
		firstTypeID, err = base.nextTypeID()
		if err != nil {
			return nil, err
		}
		id = firstTypeID
	} else {
		// Add a sentinel for Void so the we don't have to deal with
		// constant off by one issues.
		offsets = append(offsets, math.MaxInt)
	}

	var header btfType
	declTags := make(map[TypeID][]TypeID)
	for offset := 0; offset < len(raw); id++ {
		if id < firstTypeID {
			return nil, fmt.Errorf("no more type IDs")
		}

		offsets = append(offsets, offset)
		if n, err := unmarshalBtfType(&header, raw[offset:], bo); err != nil {
			return nil, fmt.Errorf("unmarshal type header for id %v: %v", id, err)
		} else {
			offset += n
		}

		if n, err := header.DataLen(); err != nil {
			return nil, err
		} else {
			offset += n
		}

		if offset > len(raw) {
			return nil, fmt.Errorf("auxiliary type data for id %v: %w", id, io.ErrUnexpectedEOF)
		}

		if header.Kind() == kindDeclTag {
			declTags[header.Type()] = append(declTags[header.Type()], id)
		}
	}

	return &decoder{
		base,
		bo,
		raw,
		strings,
		firstTypeID,
		offsets,
		declTags,
		make(map[TypeID]Type),
		make(map[TypeID][2]Bits),
	}, nil
}

func (d *decoder) inflateAll() ([]Type, error) {
	types := make([]Type, 0, len(d.offsets))
	lastTypeID := d.firstTypeID + TypeID(len(d.offsets))

	for id := d.firstTypeID; id < lastTypeID; id++ {
		typ, err := d.inflateType(id)
		if err != nil {
			return nil, err
		}
		types = append(types, typ)
	}

	return types, nil
}

func (d *decoder) inflateType(id TypeID) (typ Type, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = r.(error)
		}

		// err is the return value of the enclosing function, even if an explicit
		// return is used.
		// See https://go.dev/ref/spec#Defer_statements
		if err != nil {
			// Remove partially inflated type so that d.types only contains
			// fully inflated ones.
			delete(d.types, id)
		}
	}()

	if id < d.firstTypeID {
		return d.base.TypeByID(id)
	}

	if id == 0 {
		// Void is defined to always be type ID 0, and is thus omitted from BTF.
		// Fast-path because it is looked up frequently.
		return (*Void)(nil), nil
	}

	if typ, ok := d.types[id]; ok {
		return typ, nil
	}

	fixup := func(id TypeID, typ *Type) {
		fixup, err := d.inflateType(id)
		if err != nil {
			panic(err)
		}
		*typ = fixup
	}

	convertMembers := func(raw []btfMember, kindFlag bool) ([]Member, error) {
		members := make([]Member, 0, len(raw))
		for i, btfMember := range raw {
			name, err := d.strings.Lookup(btfMember.NameOff)
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
			data, ok := d.legacyBitfields[raw[i].Type]
			if ok {
				// Bingo!
				m.Offset += data[0]
				m.BitfieldSize = data[1]
				continue
			}
		}
		return members, nil
	}

	idx := int(id - d.firstTypeID)
	if idx >= len(d.offsets) {
		return nil, fmt.Errorf("invalid type id %v", id)
	}

	offset := d.offsets[idx]
	if offset >= len(d.raw) {
		return nil, fmt.Errorf("offset out of bounds")
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
		pos       = d.raw[offset:]
	)

	{
		if n, err := unmarshalBtfType(&header, pos, d.byteOrder); err != nil {
			return nil, fmt.Errorf("can't unmarshal type info for id %v: %v", id, err)
		} else {
			pos = pos[n:]
		}

		name, err := d.strings.Lookup(header.NameOff)
		if err != nil {
			return nil, fmt.Errorf("get name for type id %d: %w", id, err)
		}

		switch header.Kind() {
		case kindInt:
			size := header.Size()
			if _, err := unmarshalBtfInt(&bInt, pos, d.byteOrder); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfInt, id: %d: %w", id, err)
			}
			if bInt.Offset() > 0 || bInt.Bits().Bytes() != size {
				d.legacyBitfields[id] = [2]Bits{bInt.Offset(), bInt.Bits()}
			}
			typ = &Int{name, header.Size(), bInt.Encoding()}
			d.types[id] = typ

		case kindPointer:
			ptr := &Pointer{nil}
			d.types[id] = ptr

			fixup(header.Type(), &ptr.Target)
			typ = ptr

		case kindArray:
			if _, err := unmarshalBtfArray(&bArr, pos, d.byteOrder); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfArray, id: %d: %w", id, err)
			}

			arr := &Array{nil, nil, bArr.Nelems}
			d.types[id] = arr

			fixup(bArr.IndexType, &arr.Index)
			fixup(bArr.Type, &arr.Type)
			typ = arr

		case kindStruct:
			str := &Struct{name, header.Size(), nil, nil}
			d.types[id] = str

			vlen := header.Vlen()
			bMembers = slices.Grow(bMembers[:0], vlen)[:vlen]
			if _, err := unmarshalBtfMembers(bMembers, pos, d.byteOrder); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfMembers, id: %d: %w", id, err)
			}

			members, err := convertMembers(bMembers, header.Bitfield())
			if err != nil {
				return nil, fmt.Errorf("struct %s (id %d): %w", name, id, err)
			}
			str.Members = members
			typ = str

		case kindUnion:
			uni := &Union{name, header.Size(), nil, nil}
			d.types[id] = uni

			vlen := header.Vlen()
			bMembers = slices.Grow(bMembers[:0], vlen)[:vlen]
			if _, err := unmarshalBtfMembers(bMembers, pos, d.byteOrder); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfMembers, id: %d: %w", id, err)
			}

			members, err := convertMembers(bMembers, header.Bitfield())
			if err != nil {
				return nil, fmt.Errorf("union %s (id %d): %w", name, id, err)
			}
			uni.Members = members
			typ = uni

		case kindEnum:
			enum := &Enum{name, header.Size(), header.Signed(), nil}
			d.types[id] = enum

			vlen := header.Vlen()
			bEnums = slices.Grow(bEnums[:0], vlen)[:vlen]
			if _, err := unmarshalBtfEnums(bEnums, pos, d.byteOrder); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfEnums, id: %d: %w", id, err)
			}

			enum.Values = make([]EnumValue, 0, vlen)
			for i, btfVal := range bEnums {
				name, err := d.strings.Lookup(btfVal.NameOff)
				if err != nil {
					return nil, fmt.Errorf("get name for enum value %d: %s", i, err)
				}
				value := uint64(btfVal.Val)
				if enum.Signed {
					// Sign extend values to 64 bit.
					value = uint64(int32(btfVal.Val))
				}
				enum.Values = append(enum.Values, EnumValue{name, value})
			}
			typ = enum

		case kindForward:
			typ = &Fwd{name, header.FwdKind()}
			d.types[id] = typ

		case kindTypedef:
			typedef := &Typedef{name, nil, nil}
			d.types[id] = typedef

			fixup(header.Type(), &typedef.Type)
			typ = typedef

		case kindVolatile:
			volatile := &Volatile{nil}
			d.types[id] = volatile

			fixup(header.Type(), &volatile.Type)
			typ = volatile

		case kindConst:
			cnst := &Const{nil}
			d.types[id] = cnst

			fixup(header.Type(), &cnst.Type)
			typ = cnst

		case kindRestrict:
			restrict := &Restrict{nil}
			d.types[id] = restrict

			fixup(header.Type(), &restrict.Type)
			typ = restrict

		case kindFunc:
			fn := &Func{name, nil, header.Linkage(), nil, nil}
			d.types[id] = fn

			fixup(header.Type(), &fn.Type)
			typ = fn

		case kindFuncProto:
			fp := &FuncProto{}
			d.types[id] = fp

			vlen := header.Vlen()
			bParams = slices.Grow(bParams[:0], vlen)[:vlen]
			if _, err := unmarshalBtfParams(bParams, pos, d.byteOrder); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfParams, id: %d: %w", id, err)
			}

			params := make([]FuncParam, 0, vlen)
			for i, param := range bParams {
				name, err := d.strings.Lookup(param.NameOff)
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

			fixup(header.Type(), &fp.Return)
			fp.Params = params
			typ = fp

		case kindVar:
			if _, err := unmarshalBtfVariable(&bVariable, pos, d.byteOrder); err != nil {
				return nil, fmt.Errorf("can't read btfVariable, id: %d: %w", id, err)
			}

			v := &Var{name, nil, VarLinkage(bVariable.Linkage), nil}
			d.types[id] = v

			fixup(header.Type(), &v.Type)
			typ = v

		case kindDatasec:
			ds := &Datasec{name, header.Size(), nil}
			d.types[id] = ds

			vlen := header.Vlen()
			bSecInfos = slices.Grow(bSecInfos[:0], vlen)[:vlen]
			if _, err := unmarshalBtfVarSecInfos(bSecInfos, pos, d.byteOrder); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfVarSecInfos, id: %d: %w", id, err)
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
			ds.Vars = vars
			typ = ds

		case kindFloat:
			typ = &Float{name, header.Size()}
			d.types[id] = typ

		case kindDeclTag:
			if _, err := unmarshalBtfDeclTag(&bDeclTag, pos, d.byteOrder); err != nil {
				return nil, fmt.Errorf("can't read btfDeclTag, id: %d: %w", id, err)
			}

			btfIndex := bDeclTag.ComponentIdx
			if uint64(btfIndex) > math.MaxInt {
				return nil, fmt.Errorf("type id %d: index exceeds int", id)
			}

			dt := &declTag{nil, name, int(int32(btfIndex))}
			d.types[id] = dt

			fixup(header.Type(), &dt.Type)
			typ = dt

		case kindTypeTag:
			tt := &TypeTag{nil, name}
			d.types[id] = tt

			fixup(header.Type(), &tt.Type)
			typ = tt

		case kindEnum64:
			enum := &Enum{name, header.Size(), header.Signed(), nil}
			d.types[id] = enum

			vlen := header.Vlen()
			bEnums64 = slices.Grow(bEnums64[:0], vlen)[:vlen]
			if _, err := unmarshalBtfEnums64(bEnums64, pos, d.byteOrder); err != nil {
				return nil, fmt.Errorf("can't unmarshal btfEnum64s, id: %d: %w", id, err)
			}

			enum.Values = make([]EnumValue, 0, vlen)
			for i, btfVal := range bEnums64 {
				name, err := d.strings.Lookup(btfVal.NameOff)
				if err != nil {
					return nil, fmt.Errorf("get name for enum64 value %d: %s", i, err)
				}
				value := (uint64(btfVal.ValHi32) << 32) | uint64(btfVal.ValLo32)
				enum.Values = append(enum.Values, EnumValue{name, value})
			}

			typ = enum

		default:
			return nil, fmt.Errorf("type id %d: unknown kind: %v", id, header.Kind())
		}
	}

	for _, tagID := range d.declTags[id] {
		dtType, err := d.inflateType(tagID)
		if err != nil {
			return nil, err
		}

		dt, ok := dtType.(*declTag)
		if !ok {
			return nil, fmt.Errorf("type id %v: not a declTag", tagID)
		}

		switch t := typ.(type) {
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
			} else if dt.Index == -1 {
				switch t2 := t.(type) {
				case *Struct:
					t2.Tags = append(t2.Tags, dt.Value)
				case *Union:
					t2.Tags = append(t2.Tags, dt.Value)
				}
			} else {
				return nil, fmt.Errorf("type %s: decl tag for type %s has invalid component idx", dt, t)
			}

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
			} else if dt.Index == -1 {
				t.Tags = append(t.Tags, dt.Value)
			} else {
				return nil, fmt.Errorf("type %s: decl tag for type %s has invalid component idx", dt, t)
			}

		default:
			return nil, fmt.Errorf("type %s: decl tag for type %s is not supported", dt, t)
		}
	}

	return typ, nil
}
