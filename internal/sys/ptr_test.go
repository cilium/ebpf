package sys

import (
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	"github.com/go-quicktest/qt"
)

func TestTypedPointer(t *testing.T) {
	ptrs := []any{
		TypedPointer[uint32]{},
		TypedPointer[complex128]{},
		StringPointer{},
		StringSlicePointer{},
	}

	for i, a := range ptrs {
		qt.Assert(t, qt.Equals(unsafe.Alignof(a), unsafe.Alignof(unsafe.Pointer(nil))))

		for _, b := range ptrs[i+1:] {
			t.Run(fmt.Sprintf("%T %T", a, b), func(t *testing.T) {
				typeOfA := reflect.TypeOf(a)
				typeOfB := reflect.TypeOf(b)
				qt.Assert(t, qt.IsFalse(typeOfA.ConvertibleTo(typeOfB)))
			})
		}
	}
}
