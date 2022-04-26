package btf

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// builder turns Types into raw BTF.
type builder struct {
	// Remove function linkage information for compatibility with <5.6 kernels.
	StripFuncLinkage bool

	buf          *bytes.Buffer
	bo           binary.ByteOrder
	strings      *stringTableBuilder
	allocatedIDs map[Type]TypeID
	nextID       TypeID
	// Temporary storage for deflateType.
	raw rawType
}

// newBuilder returns a new builder for the given byte order.
//
// capacity is a hint for how many types the builder will be used for and may
// be zero.
func newBuilder(bo binary.ByteOrder, capacity int) *builder {
	// Reserve space for the header and one btfType per struct. This is the
	// smallest amount we can expect to use, since often used types carry extra
	// data that has to be marshaled.
	bufCap := btfHeaderLen + capacity*btfTypeLen

	return &builder{
		buf: bytes.NewBuffer(make([]byte, btfHeaderLen, bufCap)),
		bo:  bo,
		// For vmlinux, there is roughly one string per type.
		strings:      newStringTableBuilder(capacity),
		allocatedIDs: make(map[Type]TypeID, capacity),
		nextID:       1,
	}
}

// Add a Type.
//
// Adding the same Type multiple times is valid and will return a stable ID.
func (b *builder) Add(typ Type) (TypeID, error) {
	// Find all types reachable from typ, while skipping types
	// we've already added.
	types := flattenType(typ, func(t Type) bool {
		_, isVoid := t.(*Void)
		_, alreadyEncoded := b.allocatedIDs[t]
		return isVoid || alreadyEncoded
	})

	// Allocate stable IDs for types in reverse order to ensure that
	// dependencies of typ are encoded before typ. This makes decoding a lot
	// cheaper.
	for i := len(types) - 1; i >= 0; i-- {
		b.allocatedIDs[types[i]] = b.nextID
		b.nextID++
	}

	// Encode types in ID order.
	for i := len(types) - 1; i >= 0; i-- {
		if err := b.deflateType(types[i]); err != nil {
			return 0, fmt.Errorf("marshal %s: %w", types[i], err)
		}
	}

	return b.allocatedIDs[typ], nil
}

// Build the raw BTF blob.
//
// The returned slice is valid until the next call to Add.
func (b *builder) Build() ([]byte, error) {
	length := b.buf.Len()

	// Truncate the string table on return to allow adding more types.
	defer b.buf.Truncate(length)

	typeLen := uint32(length - btfHeaderLen)

	// Reserve space for the string table.
	stringLen := b.strings.Length()
	b.buf.Grow(stringLen)

	buf := b.buf.Bytes()[:length+stringLen]
	b.strings.MarshalBuffer(buf[length:])

	// Fill out the header, and write it out.
	header := &btfHeader{
		Magic:     btfMagic,
		Version:   1,
		Flags:     0,
		HdrLen:    uint32(btfHeaderLen),
		TypeOff:   0,
		TypeLen:   typeLen,
		StringOff: typeLen,
		StringLen: uint32(stringLen),
	}

	err := binary.Write(sliceWriter(buf[:btfHeaderLen]), b.bo, header)
	if err != nil {
		return nil, fmt.Errorf("can't write header: %v", err)
	}

	return buf, nil
}

func (b *builder) deflateType(typ Type) (err error) {
	raw := &b.raw
	*raw = rawType{}
	raw.NameOff, err = b.strings.Add(typ.TypeName())
	if err != nil {
		return err
	}

	switch v := typ.(type) {
	case *Int:
		raw.SetKind(kindInt)
		raw.SetSize(v.Size)

		var bi btfInt
		bi.SetEncoding(v.Encoding)
		bi.SetOffset(v.OffsetBits)
		bi.SetBits(v.Bits)
		raw.data = bi

	case *Pointer:
		raw.SetKind(kindPointer)
		raw.SetType(b.id(v.Target))

	case *Array:
		raw.SetKind(kindArray)
		raw.data = &btfArray{
			b.id(v.Type),
			b.id(v.Index),
			v.Nelems,
		}

	case *Struct:
		raw.SetKind(kindStruct)
		raw.SetSize(v.Size)
		raw.data, err = b.convertMembers(&raw.btfType, v.Members)

	case *Union:
		raw.SetKind(kindUnion)
		raw.SetSize(v.Size)
		raw.data, err = b.convertMembers(&raw.btfType, v.Members)

	case *Enum:
		raw.SetKind(kindEnum)
		raw.SetSize(v.size())
		raw.SetVlen(len(v.Values))
		raw.data, err = b.convertEnumValues(v.Values)

	case *Fwd:
		raw.SetKind(kindForward)
		raw.SetFwdKind(v.Kind)

	case *Typedef:
		raw.SetKind(kindTypedef)
		raw.SetType(b.id(v.Type))

	case *Volatile:
		raw.SetKind(kindVolatile)
		raw.SetType(b.id(v.Type))

	case *Const:
		raw.SetKind(kindConst)
		raw.SetType(b.id(v.Type))

	case *Restrict:
		raw.SetKind(kindRestrict)
		raw.SetType(b.id(v.Type))

	case *Func:
		raw.SetKind(kindFunc)
		raw.SetType(b.id(v.Type))
		if !b.StripFuncLinkage {
			raw.SetLinkage(v.Linkage)
		}

	case *FuncProto:
		raw.SetKind(kindFuncProto)
		raw.SetType(b.id(v.Return))
		raw.SetVlen(len(v.Params))
		raw.data, err = b.convertFuncParams(v.Params)

	case *Var:
		raw.SetKind(kindVar)
		raw.SetType(b.id(v.Type))
		raw.data = btfVariable{uint32(v.Linkage)}

	case *Datasec:
		raw.SetKind(kindDatasec)
		raw.SetSize(v.Size)
		raw.SetVlen(len(v.Vars))
		raw.data = b.convertVarSecinfos(v.Vars)

	case *Float:
		raw.SetKind(kindFloat)
		raw.SetSize(v.Size)

	default:
		return fmt.Errorf("don't know how to deflate %T", v)
	}

	if err != nil {
		return err
	}

	return raw.Marshal(b.buf, b.bo)
}

func (b *builder) id(typ Type) TypeID {
	// We can't lookup *Void from b.ids since zero-sized types may or may not
	// have identical addresses according to the Go spec. Use a type assertion
	// instead.
	if _, ok := typ.(*Void); ok {
		return 0
	}

	return b.allocatedIDs[typ]
}

func (b *builder) convertMembers(header *btfType, members []Member) ([]btfMember, error) {
	bms := make([]btfMember, 0, len(members))
	isBitfield := false
	for _, member := range members {
		isBitfield = isBitfield || member.BitfieldSize > 0

		offset := member.OffsetBits
		if isBitfield {
			offset = member.BitfieldSize<<24 | (member.OffsetBits & 0xffffff)
		}

		nameOff, err := b.strings.Add(member.Name)
		if err != nil {
			return nil, err
		}

		bms = append(bms, btfMember{
			nameOff,
			b.id(member.Type),
			offset,
		})
	}

	header.SetVlen(len(members))
	header.SetBitfield(isBitfield)
	return bms, nil
}

func (b *builder) convertEnumValues(values []EnumValue) ([]btfEnum, error) {
	bes := make([]btfEnum, 0, len(values))
	for _, value := range values {
		nameOff, err := b.strings.Add(value.Name)
		if err != nil {
			return nil, err
		}

		bes = append(bes, btfEnum{
			nameOff,
			value.Value,
		})
	}
	return bes, nil
}

func (b *builder) convertFuncParams(params []FuncParam) ([]btfParam, error) {
	bps := make([]btfParam, 0, len(params))
	for _, param := range params {
		nameOff, err := b.strings.Add(param.Name)
		if err != nil {
			return nil, err
		}

		bps = append(bps, btfParam{
			nameOff,
			b.id(param.Type),
		})
	}
	return bps, nil
}

func (b *builder) convertVarSecinfos(vars []VarSecinfo) []btfVarSecinfo {
	vsis := make([]btfVarSecinfo, 0, len(vars))
	for _, v := range vars {
		vsis = append(vsis, btfVarSecinfo{
			b.id(v.Type),
			v.Offset,
			v.Size,
		})
	}
	return vsis
}
