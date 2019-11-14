package btf

import (
	"encoding/binary"
	"io"
	"io/ioutil"

	"github.com/pkg/errors"
)

type btfKind uint8

const (
	kindVoid btfKind = iota
	kindInt
	kindPointer
	kindArray
	kindStruct
	kindUnion
	kindEnum
	kindForward
	kindTypedef
	kindVolatile
	kindConst
	kindRestrict
	// Added ~4.20
	kindFunc
	kindFuncProto
	// Added ~5.1
	kindVar
	kindDatasec
)

const (
	btfTypeKindShift = 24
	btfTypeKindLen   = 4
	btfTypeVlenShift = 0
	btfTypeVlenMask  = 16
)

// Based on struct btf_type in Documentation/bpf/btf.rst
type btfType struct {
	NameOff uint32
	/* "info" bits arrangement
	 * bits  0-15: vlen (e.g. # of struct's members)
	 * bits 16-23: unused
	 * bits 24-27: kind (e.g. int, ptr, array...etc)
	 * bits 28-30: unused
	 * bit     31: kind_flag, currently used by
	 *             struct, union and fwd
	 */
	Info uint32
	/* "size" is used by INT, ENUM, STRUCT and UNION.
	 * "size" tells the size of the type it is describing.
	 *
	 * "type" is used by PTR, TYPEDEF, VOLATILE, CONST, RESTRICT,
	 * FUNC and FUNC_PROTO.
	 * "type" is a type_id referring to another type.
	 */
	SizeType uint32
}

func mask(len uint32) uint32 {
	return (1 << len) - 1
}

func (bt *btfType) info(len, shift uint32) uint32 {
	return (bt.Info >> shift) & mask(len)
}

func (bt *btfType) setInfo(value, len, shift uint32) {
	bt.Info &^= mask(len) << shift
	bt.Info |= (value & mask(len)) << shift
}

func (bt *btfType) Kind() btfKind {
	return btfKind(bt.info(btfTypeKindLen, btfTypeKindShift))
}

func (bt *btfType) SetKind(kind btfKind) {
	bt.setInfo(uint32(kind), btfTypeKindLen, btfTypeKindShift)
}

func (bt *btfType) Vlen() int {
	return int(bt.info(btfTypeVlenMask, btfTypeVlenShift))
}

func (bt *btfType) SetVlen(vlen int) {
	bt.setInfo(uint32(vlen), btfTypeVlenMask, btfTypeVlenShift)
}

func (bt *btfType) Size() int {
	switch bt.Kind() {
	case kindInt:
		return 4 // sizeof(uint32)
	case kindPointer:
		return 0
	case kindArray:
		return 4 * 3 // sizeof(struct btf_array)
	case kindStruct:
		fallthrough
	case kindUnion:
		return bt.Vlen() * 4 * 3 // sizeof(struct btf_member)
	case kindEnum:
		return bt.Vlen() * 4 * 2 // sizeof(struct btf_enum)
	case kindForward:
		return 0
	case kindTypedef:
		return 0
	case kindVolatile:
		return 0
	case kindConst:
		return 0
	case kindRestrict:
		return 0
	case kindFunc:
		return 0
	case kindFuncProto:
		return bt.Vlen() * 4 * 2 // sizeof(struct btf_param)
	case kindVar:
		return 4 // sizeof(struct btf_variable)
	case kindDatasec:
		return bt.Vlen() * 4 * 3 // sizeof(struct btf_var_secinfo)
	default:
		return -1
	}
}

type typeID uint32

func readTypes(r io.Reader, bo binary.ByteOrder, strings map[uint32]string) (map[string][]typeID, error) {
	var (
		t       btfType
		typeIDs = make(map[string][]typeID)
	)

	for id := typeID(1); ; id++ {
		if err := binary.Read(r, bo, &t); err == io.EOF {
			return typeIDs, nil
		} else if err != nil {
			return nil, errors.Wrapf(err, "can't read type info for id %v", id)
		}

		name, ok := strings[t.NameOff]
		if !ok {
			return nil, errors.Errorf("type id %v: no valid name at offset %v", id, t.NameOff)
		}

		if name != "" {
			typeIDs[name] = append(typeIDs[name], id)
		}

		size := t.Size()
		if size < 0 {
			return nil, errors.Errorf("type id %v: kind %v: invalid size", id, t.Kind())
		}
		if size == 0 {
			continue
		}

		// It would be more efficient to take an io.ReadSeeker, and
		// then skip the bits we don't care about. However Seek doesn't
		// compose well with io.LimitReader, so we just keep Read()ing
		// instead. This should be fine since most of the time we'll only
		// skip a few bytes.
		_, err := io.CopyN(ioutil.Discard, r, int64(size))
		if err != nil {
			return nil, errors.Wrapf(err, "can't skip additional data for id %v", id)
		}
	}
}
