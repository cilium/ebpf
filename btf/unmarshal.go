package btf

import (
	"encoding/binary"
	"fmt"
	"io"
	"iter"
	"maps"
	"math"
	"slices"
	"sync"
)

type decoder struct {
	// Immutable fields, may be shared.

	base      *decoder
	byteOrder binary.ByteOrder
	raw       []byte
	strings   *stringTable
	// The ID for offsets[0].
	firstTypeID TypeID
	// Map from TypeID to offset of the marshaled data in raw. Contains an entry
	// for each TypeID, including 0 aka Void. The offset for Void is invalid.
	offsets    []int
	declTags   map[TypeID][]TypeID
	namedTypes map[essentialName][]TypeID

	// Protection for mutable fields below.
	mu              sync.Mutex
	types           map[TypeID]Type
	typeIDs         map[Type]TypeID
	legacyBitfields map[TypeID][2]Bits // offset, size
}

func newDecoder(raw []byte, bo binary.ByteOrder, strings *stringTable, base *decoder) (*decoder, error) {
	firstTypeID := TypeID(0)
	if base != nil {
		if base.byteOrder != bo {
			return nil, fmt.Errorf("can't use %v base with %v split BTF", base.byteOrder, bo)
		}

		if base.firstTypeID != 0 {
			return nil, fmt.Errorf("can't use split BTF as base")
		}

		base = base.Copy()
		firstTypeID = TypeID(len(base.offsets))
	}

	var header btfType
	var numTypes, numDeclTags, numNamedTypes int

	for _, err := range allBtfTypeOffsets(raw, bo, &header) {
		if err != nil {
			return nil, err
		}

		numTypes++

		if header.Kind() == kindDeclTag {
			numDeclTags++
		}

		if header.NameOff != 0 {
			numNamedTypes++
		}
	}

	if firstTypeID == 0 {
		// Allocate an extra slot for Void so we don't have to deal with
		// constant off by one issues.
		numTypes++
	}

	offsets := make([]int, 0, numTypes)
	declTags := make(map[TypeID][]TypeID, numDeclTags)
	namedTypes := make(map[essentialName][]TypeID, numNamedTypes)

	if firstTypeID == 0 {
		// Add a sentinel for Void.
		offsets = append(offsets, math.MaxInt)
	}

	id := firstTypeID + TypeID(len(offsets))
	for offset := range allBtfTypeOffsets(raw, bo, &header) {
		if id < firstTypeID {
			return nil, fmt.Errorf("no more type IDs")
		}

		offsets = append(offsets, offset)

		if header.Kind() == kindDeclTag {
			declTags[header.Type()] = append(declTags[header.Type()], id)
		}

		// Build named type index.
		name, err := strings.Lookup(header.NameOff)
		if err != nil {
			return nil, fmt.Errorf("lookup type name for id %v: %w", id, err)
		}

		if name := newEssentialName(name); name != "" {
			namedTypes[name] = append(namedTypes[name], id)
		}

		id++
	}

	return &decoder{
		base,
		bo,
		raw,
		strings,
		firstTypeID,
		offsets,
		declTags,
		namedTypes,
		sync.Mutex{},
		make(map[TypeID]Type),
		make(map[Type]TypeID),
		make(map[TypeID][2]Bits),
	}, nil
}

func allBtfTypeOffsets(buf []byte, bo binary.ByteOrder, header *btfType) iter.Seq2[int, error] {
	return func(yield func(int, error) bool) {
		for offset := 0; offset < len(buf); {
			start := offset

			n, err := unmarshalBtfType(header, buf[offset:], bo)
			if err != nil {
				yield(-1, fmt.Errorf("unmarshal type header: %w", err))
				return
			}
			offset += n

			n, err = header.DataLen()
			if err != nil {
				yield(-1, err)
				return
			}
			offset += n

			if offset > len(buf) {
				yield(-1, fmt.Errorf("auxiliary type data: %w", io.ErrUnexpectedEOF))
				return
			}

			if !yield(start, nil) {
				return
			}
		}
	}
}

func (d *decoder) Copy() *decoder {
	if d == nil {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	types := make(map[TypeID]Type, len(d.types))
	copiedTypes := make(map[Type]Type, len(d.types))
	typeIDs := make(map[Type]TypeID, len(d.typeIDs))
	for id, typ := range d.types {
		types[id] = copyType(typ, d.typeIDs, copiedTypes, typeIDs)
	}

	return &decoder{
		d.base,
		d.byteOrder,
		d.raw,
		d.strings,
		d.firstTypeID,
		d.offsets,
		d.declTags,
		d.namedTypes,
		sync.Mutex{},
		types,
		typeIDs,
		maps.Clone(d.legacyBitfields),
	}
}

// TypeID returns the ID for a Type previously obtained via [TypeByID].
func (d *decoder) TypeID(typ Type) (TypeID, error) {
	if _, ok := typ.(*Void); ok {
		// Equality is weird for void, since it is a zero sized type.
		return 0, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	id, ok := d.typeIDs[typ]
	if !ok {
		return 0, fmt.Errorf("no ID for type %s: %w", typ, ErrNotFound)
	}

	return id, nil
}

// TypeIDsByName returns all type IDs which have the given essential name.
//
// The returned slice must not be modified.
func (d *decoder) TypeIDsByName(name essentialName) []TypeID {
	return d.namedTypes[name]
}

// TypeByID decodes a type and any of its descendants.
func (d *decoder) TypeByID(id TypeID) (Type, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	return d.inflateType(id)
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
		} else {
			// Populate reverse index.
			d.typeIDs[typ] = id
		}
	}()

	if id < d.firstTypeID {
		return d.base.inflateType(id)
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
		return nil, fmt.Errorf("type id %v: %w", id, ErrNotFound)
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
