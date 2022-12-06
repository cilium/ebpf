package btf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"sync"

	"github.com/cilium/ebpf/internal"
)

type marshalOptions struct {
	// Remove function linkage information for compatibility with <5.6 kernels.
	StripFuncLinkage bool
}

// kernelMarshalOptions will generate BTF suitable for the current kernel.
var kernelMarshalOptions = &marshalOptions{
	StripFuncLinkage: haveFuncLinkage() != nil,
}

// encoder turns Types into raw BTF.
type encoder struct {
	marshalOptions

	byteOrder binary.ByteOrder
	buf       *bytes.Buffer
	strings   *stringTableBuilder
	ids       map[Type]TypeID
}

var emptyBTFHeader = make([]byte, btfHeaderLen)

var bufferPool = sync.Pool{
	New: func() any {
		return bytes.NewBuffer(make([]byte, btfHeaderLen+128))
	},
}

// marshalSpec encodes a spec into BTF wire format.
//
// Doesn't support encoding split BTF since it's not possible to load
// that into the kernel and we don't have a use case for writing BTF
// out again.
//
// w should be retrieved from bufferPool. opts may be nil.
func marshalSpec(w *bytes.Buffer, s *Spec, stb *stringTableBuilder, opts *marshalOptions) (err error) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}

		var ok bool
		err, ok = r.(error)
		if !ok {
			panic(r)
		}
	}()

	numStrings := 0
	if s.strings != nil {
		// Use the ELF string table as an estimate of the final
		// string table size. We don't use the ELF string
		// table since the types may have been changed in the meantime.
		numStrings = s.strings.Length()
	}

	if stb == nil {
		stb = newStringTableBuilder(numStrings)
	}

	e := encoder{
		byteOrder: internal.NativeEndian,
		buf:       w,
		strings:   stb,
		ids:       s.typeIDs,
	}

	if opts != nil {
		e.marshalOptions = *opts
	}

	// Reserve space for the BTF header.
	e.buf.Write(emptyBTFHeader)

	var raw rawType
	for _, typ := range s.types {
		if err := e.deflateType(typ, &raw); err != nil {
			return fmt.Errorf("deflate %s: %w", typ, err)
		}
	}

	length := e.buf.Len()
	typeLen := uint32(length - btfHeaderLen)

	// Reserve space for the string table.
	stringLen := e.strings.Length()
	e.buf.Grow(stringLen)
	buf := e.strings.AppendEncoded(e.buf.Bytes())

	// Add string table to the unread portion of the buffer, otherwise
	// it isn't return by Bytes().
	// The copy is optimized out since src == dst.
	e.buf.Write(buf[length:])

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

	err = binary.Write(sliceWriter(buf[:btfHeaderLen]), e.byteOrder, header)
	if err != nil {
		return fmt.Errorf("write header: %v", err)
	}

	return nil
}

// id returns the ID for the given type or panics with an error.
func (e *encoder) id(typ Type) TypeID {
	if _, ok := typ.(*Void); ok {
		return 0
	}

	id, ok := e.ids[typ]
	if !ok {
		panic(fmt.Errorf("no ID for type %s", typ))
	}

	return id
}

func (e *encoder) deflateType(typ Type, raw *rawType) (err error) {
	*raw = rawType{}
	raw.NameOff, err = e.strings.Add(typ.TypeName())
	if err != nil {
		return err
	}

	switch v := typ.(type) {
	case *Void:
		return nil

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
		raw.SetType(e.id(v.Target))

	case *Array:
		raw.SetKind(kindArray)
		raw.data = &btfArray{
			e.id(v.Type),
			e.id(v.Index),
			v.Nelems,
		}

	case *Struct:
		raw.SetKind(kindStruct)
		raw.SetSize(v.Size)
		raw.data, err = e.convertMembers(&raw.btfType, v.Members)

	case *Union:
		raw.SetKind(kindUnion)
		raw.SetSize(v.Size)
		raw.data, err = e.convertMembers(&raw.btfType, v.Members)

	case *Enum:
		raw.SetSize(v.size())
		raw.SetVlen(len(v.Values))
		raw.SetSigned(v.Signed)

		if v.has64BitValues() {
			raw.SetKind(kindEnum64)
			raw.data, err = e.deflateEnum64Values(v.Values)
		} else {
			raw.SetKind(kindEnum)
			raw.data, err = e.deflateEnumValues(v.Values)
		}

	case *Fwd:
		raw.SetKind(kindForward)
		raw.SetFwdKind(v.Kind)

	case *Typedef:
		raw.SetKind(kindTypedef)
		raw.SetType(e.id(v.Type))

	case *Volatile:
		raw.SetKind(kindVolatile)
		raw.SetType(e.id(v.Type))

	case *Const:
		raw.SetKind(kindConst)
		raw.SetType(e.id(v.Type))

	case *Restrict:
		raw.SetKind(kindRestrict)
		raw.SetType(e.id(v.Type))

	case *Func:
		raw.SetKind(kindFunc)
		raw.SetType(e.id(v.Type))
		if !e.StripFuncLinkage {
			raw.SetLinkage(v.Linkage)
		}

	case *FuncProto:
		raw.SetKind(kindFuncProto)
		raw.SetType(e.id(v.Return))
		raw.SetVlen(len(v.Params))
		raw.data, err = e.deflateFuncParams(v.Params)

	case *Var:
		raw.SetKind(kindVar)
		raw.SetType(e.id(v.Type))
		raw.data = btfVariable{uint32(v.Linkage)}

	case *Datasec:
		raw.SetKind(kindDatasec)
		raw.SetSize(v.Size)
		raw.SetVlen(len(v.Vars))
		raw.data = e.deflateVarSecinfos(v.Vars)

	case *Float:
		raw.SetKind(kindFloat)
		raw.SetSize(v.Size)

	case *declTag:
		raw.SetKind(kindDeclTag)
		raw.data = &btfDeclTag{uint32(v.Index)}

	case *typeTag:
		raw.SetKind(kindTypeTag)
		raw.NameOff, err = e.strings.Add(v.Value)

	default:
		return fmt.Errorf("don't know how to deflate %T", v)
	}

	if err != nil {
		return err
	}

	return raw.Marshal(e.buf, e.byteOrder)
}

func (e *encoder) convertMembers(header *btfType, members []Member) ([]btfMember, error) {
	bms := make([]btfMember, 0, len(members))
	isBitfield := false
	for _, member := range members {
		isBitfield = isBitfield || member.BitfieldSize > 0

		offset := member.Offset
		if isBitfield {
			offset = member.BitfieldSize<<24 | (member.Offset & 0xffffff)
		}

		nameOff, err := e.strings.Add(member.Name)
		if err != nil {
			return nil, err
		}

		bms = append(bms, btfMember{
			nameOff,
			e.id(member.Type),
			uint32(offset),
		})
	}

	header.SetVlen(len(members))
	header.SetBitfield(isBitfield)
	return bms, nil
}

func (e *encoder) deflateEnumValues(values []EnumValue) ([]btfEnum, error) {
	bes := make([]btfEnum, 0, len(values))
	for _, value := range values {
		nameOff, err := e.strings.Add(value.Name)
		if err != nil {
			return nil, err
		}

		if value.Value > math.MaxUint32 {
			return nil, fmt.Errorf("value of enum %q exceeds 32 bits", value.Name)
		}

		bes = append(bes, btfEnum{
			nameOff,
			uint32(value.Value),
		})
	}

	return bes, nil
}

func (e *encoder) deflateEnum64Values(values []EnumValue) ([]btfEnum64, error) {
	bes := make([]btfEnum64, 0, len(values))
	for _, value := range values {
		nameOff, err := e.strings.Add(value.Name)
		if err != nil {
			return nil, err
		}

		bes = append(bes, btfEnum64{
			nameOff,
			uint32(value.Value),
			uint32(value.Value >> 32),
		})
	}

	return bes, nil
}

func (e *encoder) deflateFuncParams(params []FuncParam) ([]btfParam, error) {
	bps := make([]btfParam, 0, len(params))
	for _, param := range params {
		nameOff, err := e.strings.Add(param.Name)
		if err != nil {
			return nil, err
		}

		bps = append(bps, btfParam{
			nameOff,
			e.id(param.Type),
		})
	}
	return bps, nil
}

func (e *encoder) deflateVarSecinfos(vars []VarSecinfo) []btfVarSecinfo {
	vsis := make([]btfVarSecinfo, 0, len(vars))
	for _, v := range vars {
		vsis = append(vsis, btfVarSecinfo{
			e.id(v.Type),
			v.Offset,
			v.Size,
		})
	}
	return vsis
}

// MarshalMapKV creates a BTF object containing a map key and value.
//
// The function is intended for the use of the ebpf package and may be removed
// at any point in time.
func MarshalMapKV(key, value Type) (_ *Handle, keyID, valueID TypeID, err error) {
	spec := NewSpec()

	if key != nil {
		keyID, err = spec.Add(key)
		if err != nil {
			return nil, 0, 0, err
		}
	}

	if value != nil {
		valueID, err = spec.Add(value)
		if err != nil {
			return nil, 0, 0, err
		}
	}

	handle, err := NewHandle(spec)
	if err != nil {
		// Check for 'full' map BTF support, since kernels between 4.18 and 5.2
		// already support BTF blobs for maps without Var or Datasec just fine.
		if err := haveMapBTF(); err != nil {
			return nil, 0, 0, err
		}
	}
	return handle, keyID, valueID, err
}
