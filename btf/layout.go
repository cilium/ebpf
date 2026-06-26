package btf

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

var btfLayoutLen = int(unsafe.Sizeof(btfLayout{}))

type btfLayout struct {
	InfoSize byte
	ElemSize byte
	Flags    uint16
}

func parseLayouts(bytes []byte, bo binary.ByteOrder) (btfLayouts, error) {
	layouts := make([]btfLayout, len(bytes)/binary.Size(btfLayout{}))
	_, err := binary.Decode(bytes, bo, layouts)
	if err != nil {
		return nil, err
	}
	return layouts, nil
}

type btfLayouts []btfLayout

func (b btfLayouts) kindSize(kind btfKind, vlen int) (size int, err error) {
	if int(kind) >= len(b) {
		return 0, fmt.Errorf("unknown kind: %d", kind)
	}

	layout := b[kind]
	return int(layout.InfoSize) + int(layout.ElemSize)*int(vlen), nil
}

func builtinLayouts() btfLayouts {
	return btfLayouts{
		{InfoSize: 0, ElemSize: 0},                                    // kindUnknown
		{InfoSize: byte(unsafe.Sizeof(btfInt{})), ElemSize: 0},        // kindInt
		{InfoSize: 0, ElemSize: 0},                                    // kindPointer
		{InfoSize: byte(unsafe.Sizeof(btfArray{})), ElemSize: 0},      // kindArray
		{InfoSize: 0, ElemSize: byte(unsafe.Sizeof(btfMember{}))},     // kindStruct
		{InfoSize: 0, ElemSize: byte(unsafe.Sizeof(btfMember{}))},     // kindUnion
		{InfoSize: 0, ElemSize: byte(unsafe.Sizeof(btfEnum{}))},       // kindEnum
		{InfoSize: 0, ElemSize: 0},                                    // kindForward
		{InfoSize: 0, ElemSize: 0},                                    // kindTypedef
		{InfoSize: 0, ElemSize: 0},                                    // kindVolatile
		{InfoSize: 0, ElemSize: 0},                                    // kindConst
		{InfoSize: 0, ElemSize: 0},                                    // kindRestrict
		{InfoSize: 0, ElemSize: 0},                                    // kindFunc
		{InfoSize: 0, ElemSize: byte(unsafe.Sizeof(btfParam{}))},      // kindFuncProto
		{InfoSize: byte(unsafe.Sizeof(btfVariable{})), ElemSize: 0},   // kindVar
		{InfoSize: 0, ElemSize: byte(unsafe.Sizeof(btfVarSecinfo{}))}, // kindDatasec
		{InfoSize: 0, ElemSize: 0},                                    // kindFloat
		{InfoSize: byte(unsafe.Sizeof(btfDeclTag{})), ElemSize: 0},    // kindDeclTag
		{InfoSize: 0, ElemSize: 0},                                    // kindTypeTag
		{InfoSize: 0, ElemSize: byte(unsafe.Sizeof(btfEnum64{}))},     // kindEnum64
	}
}
