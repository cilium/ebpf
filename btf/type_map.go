package btf

import (
	"reflect"
	"unsafe"
)

// typeMap is a faster alternative to a map[Type]V.
//
// Using an interface as the key to a map is quite slow, so we use unsafe tricks
// to only use the pointer part of a Type interface as the key. This way we
// benefit from 64 bit key optimizations in the runtime map implementation.
type typeMap[V any] map[typeKey]V

func (tm typeMap[V]) Set(k Type, v V) {
	tm[newTypeKey(k)] = v
}

func (tm typeMap[V]) Get(k Type) (V, bool) {
	v, ok := tm[newTypeKey(k)]
	return v, ok
}

type typeKey struct {
	// A pointer which uniquely identifies a value that implements Type. This is
	// not always a pointer to a value, see newTypeKey.
	//
	// YOU MUST NOT CAST THIS TO A TYPE.
	ptr unsafe.Pointer
}

var voidTypeID = typeKey{reflect.ValueOf(reflect.TypeOf(&Void{})).UnsafePointer()}

func newTypeKey(t Type) typeKey {
	switch t.(type) {
	case *Void:
		// We assume that the address of a Type value is unique, and can therefore
		// be used as a key. There is one minor hitch:
		//
		//     Two distinct zero-size variables may have the same address in memory.
		//     https://go.dev/ref/spec#Size_and_alignment_guarantees
		//
		// A variable with a zero sized type is not required to always have the
		// same pointer. Since Void is zero sized, we may end up with multiple
		// entries for a void type.
		//
		// Instead, we use the pointer to the reflect.Type as the ID.
		return voidTypeID
	default:
		// This assumes that all implementations of Type use pointer receivers.
		return typeKey{reflect.ValueOf(t).UnsafePointer()}
	}
}
