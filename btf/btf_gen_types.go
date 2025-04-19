// Code generated by btf/cmd/genbtftypes; DO NOT EDIT.

package btf

type btfArray struct {
	Type      TypeID
	IndexType TypeID
	Nelems    uint32
}

type btfDeclTag struct{ ComponentIdx uint32 }

type btfEnum struct {
	NameOff uint32
	Val     uint32
}

type btfEnum64 struct {
	NameOff uint32
	ValLo32 uint32
	ValHi32 uint32
}

type btfHeader struct {
	Magic     uint16
	Version   uint8
	Flags     uint8
	HdrLen    uint32
	TypeOff   uint32
	TypeLen   uint32
	StringOff uint32
	StringLen uint32
}

type btfMember struct {
	NameOff uint32
	Type    TypeID
	Offset  uint32
}

type btfParam struct {
	NameOff uint32
	Type    TypeID
}

type btfType struct {
	NameOff  uint32
	Info     uint32
	SizeType uint32
}

type btfVarSecinfo struct {
	Type   TypeID
	Offset uint32
	Size   uint32
}

type btfVariable struct{ Linkage uint32 }
