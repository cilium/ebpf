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
	kindFunc
	kindFuncProto
)

type btfType struct {
	NameOff  uint32
	Info     uint32
	SizeType uint32
}

func (bt *btfType) kind() btfKind {
	return btfKind(((bt.Info) >> 24) & 0x0f)
}

func (bt *btfType) vlen() int {
	return int(bt.Info & 0xffff)
}

func (bt *btfType) size() int {
	switch bt.kind() {
	case kindInt:
		return 4 // sizeof(uint32)
	case kindArray:
		return 4 * 3 // sizeof(struct btf_array)
	case kindStruct:
		fallthrough
	case kindUnion:
		return bt.vlen() * 4 * 3 // sizeof(struct btf_member)
	case kindEnum:
		return bt.vlen() * 4 * 2 // sizeof(struct btf_enum)
	case kindFuncProto:
		return bt.vlen() * 4 * 2 // sizeof(struct btf_param)
	default:
		return 0
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

		size := t.size()
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
