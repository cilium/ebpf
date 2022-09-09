package btf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/cilium/ebpf/internal"
)

type EncoderOptions struct {
	ByteOrder binary.ByteOrder
	// Remove function linkage information for compatibility with <5.6 kernels.
	StripFuncLinkage bool
}

// KernelEncoderOptions will generate BTF suitable for the current kernel.
var KernelEncoderOptions EncoderOptions

func init() {
	KernelEncoderOptions = EncoderOptions{
		ByteOrder:        internal.NativeEndian,
		StripFuncLinkage: haveFuncLinkage() != nil,
	}
}

// Encoder turns Types into raw BTF.
type Encoder struct {
	opts EncoderOptions

	buf          *bytes.Buffer
	strings      *stringTableBuilder
	allocatedIDs map[Type]TypeID
	nextID       TypeID
	pending      internal.Deque[Type]
	// Temporary storage for deflateType.
	raw rawType
}

// NewEncoder returns a new builder for the given byte order.
//
// See [KernelEncoderOptions] to build BTF for the current system.
func NewEncoder(opts EncoderOptions) *Encoder {
	return newEncoder(opts, nil)
}

func newEncoder(opts EncoderOptions, strings *stringTableBuilder) *Encoder {
	enc := &Encoder{
		opts: opts,
		buf:  bytes.NewBuffer(make([]byte, btfHeaderLen)),
	}
	enc.reset(strings)
	return enc
}

// Reset internal state to be able to reuse the Encoder.
func (b *Encoder) Reset() {
	b.reset(nil)
}

func (b *Encoder) reset(strings *stringTableBuilder) {
	if strings == nil {
		strings = newStringTableBuilder()
	}

	b.buf.Truncate(btfHeaderLen)
	b.strings = strings
	b.allocatedIDs = make(map[Type]TypeID)
	b.nextID = 1
}

// Add a Type.
//
// Adding the same Type multiple times is valid and will return a stable ID.
func (b *Encoder) Add(typ Type) (TypeID, error) {
	iter := postorderTraversal(typ, func(t Type) (skip bool) {
		_, isVoid := t.(*Void)
		_, alreadyEncoded := b.allocatedIDs[t]
		return isVoid || alreadyEncoded
	})

	for iter.Next() {
		// Allocate an ID for the next type and push it to pending if necessary.
		b.allocateID(iter.Type)

		// Deflate types until there is nothing more to do. deflateType may
		// push more types via b.allocateID.
		for !b.pending.Empty() {
			t := b.pending.Shift()
			if err := b.deflateType(t); err != nil {
				return 0, fmt.Errorf("marshal %s: %w", t, err)
			}
		}
	}

	return b.allocatedIDs[typ], nil
}

// Encode the raw BTF blob.
//
// The returned slice is valid until the next call to Add.
func (b *Encoder) Encode() ([]byte, error) {
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

	err := binary.Write(sliceWriter(buf[:btfHeaderLen]), b.opts.ByteOrder, header)
	if err != nil {
		return nil, fmt.Errorf("can't write header: %v", err)
	}

	return buf, nil
}

func (b *Encoder) deflateType(typ Type) (err error) {
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
		// We need to set bits in addition to size, since btf_type_int_is_regular
		// otherwise flags this as a bitfield.
		bi.SetBits(byte(v.Size) * 8)
		raw.data = bi

	case *Pointer:
		raw.SetKind(kindPointer)
		raw.SetType(b.allocateID(v.Target))

	case *Array:
		raw.SetKind(kindArray)
		raw.data = &btfArray{
			b.allocateID(v.Type),
			b.allocateID(v.Index),
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
		raw.SetSigned(v.Signed)
		raw.data, err = b.convertEnumValues(v.Values)

	case *Fwd:
		raw.SetKind(kindForward)
		raw.SetFwdKind(v.Kind)

	case *Typedef:
		raw.SetKind(kindTypedef)
		raw.SetType(b.allocateID(v.Type))

	case *Volatile:
		raw.SetKind(kindVolatile)
		raw.SetType(b.allocateID(v.Type))

	case *Const:
		raw.SetKind(kindConst)
		raw.SetType(b.allocateID(v.Type))

	case *Restrict:
		raw.SetKind(kindRestrict)
		raw.SetType(b.allocateID(v.Type))

	case *Func:
		raw.SetKind(kindFunc)
		raw.SetType(b.allocateID(v.Type))
		if !b.opts.StripFuncLinkage {
			raw.SetLinkage(v.Linkage)
		}

	case *FuncProto:
		raw.SetKind(kindFuncProto)
		raw.SetType(b.allocateID(v.Return))
		raw.SetVlen(len(v.Params))
		raw.data, err = b.convertFuncParams(v.Params)

	case *Var:
		raw.SetKind(kindVar)
		raw.SetType(b.allocateID(v.Type))
		raw.data = btfVariable{uint32(v.Linkage)}

	case *Datasec:
		raw.SetKind(kindDatasec)
		raw.SetSize(v.Size)
		raw.SetVlen(len(v.Vars))
		raw.data = b.convertVarSecinfos(v.Vars)

	case *Float:
		raw.SetKind(kindFloat)
		raw.SetSize(v.Size)

	case *declTag:
		raw.SetKind(kindDeclTag)
		raw.data = &btfDeclTag{uint32(v.Index)}

	case *typeTag:
		raw.SetKind(kindTypeTag)
		raw.NameOff, err = b.strings.Add(v.Value)

	default:
		return fmt.Errorf("don't know how to deflate %T", v)
	}

	if err != nil {
		return err
	}

	return raw.Marshal(b.buf, b.opts.ByteOrder)
}

func (b *Encoder) allocateID(typ Type) TypeID {
	// We can't lookup *Void from b.ids since zero-sized types may or may not
	// have identical addresses according to the Go spec. Use a type assertion
	// instead.
	if _, ok := typ.(*Void); ok {
		return 0
	}

	id, ok := b.allocatedIDs[typ]
	if ok {
		return id
	}

	// This is a type we haven't seen before. Allocate and ID and make sure it's
	// deflated in the correct order.
	id = b.nextID
	b.allocatedIDs[typ] = id
	b.nextID++

	b.pending.Push(typ)
	return id
}

func (b *Encoder) convertMembers(header *btfType, members []Member) ([]btfMember, error) {
	bms := make([]btfMember, 0, len(members))
	isBitfield := false
	for _, member := range members {
		isBitfield = isBitfield || member.BitfieldSize > 0

		offset := member.Offset
		if isBitfield {
			offset = member.BitfieldSize<<24 | (member.Offset & 0xffffff)
		}

		nameOff, err := b.strings.Add(member.Name)
		if err != nil {
			return nil, err
		}

		bms = append(bms, btfMember{
			nameOff,
			b.allocateID(member.Type),
			uint32(offset),
		})
	}

	header.SetVlen(len(members))
	header.SetBitfield(isBitfield)
	return bms, nil
}

func (b *Encoder) convertEnumValues(values []EnumValue) ([]btfEnum, error) {
	bes := make([]btfEnum, 0, len(values))
	for _, value := range values {
		nameOff, err := b.strings.Add(value.Name)
		if err != nil {
			return nil, err
		}

		if value.Value > math.MaxUint32 {
			return nil, fmt.Errorf("value of enum %q exceeds 32 bit", value.Name)
		}

		bes = append(bes, btfEnum{
			nameOff,
			uint32(value.Value),
		})
	}
	return bes, nil
}

func (b *Encoder) convertFuncParams(params []FuncParam) ([]btfParam, error) {
	bps := make([]btfParam, 0, len(params))
	for _, param := range params {
		nameOff, err := b.strings.Add(param.Name)
		if err != nil {
			return nil, err
		}

		bps = append(bps, btfParam{
			nameOff,
			b.allocateID(param.Type),
		})
	}
	return bps, nil
}

func (b *Encoder) convertVarSecinfos(vars []VarSecinfo) []btfVarSecinfo {
	vsis := make([]btfVarSecinfo, 0, len(vars))
	for _, v := range vars {
		vsis = append(vsis, btfVarSecinfo{
			b.allocateID(v.Type),
			v.Offset,
			v.Size,
		})
	}
	return vsis
}
