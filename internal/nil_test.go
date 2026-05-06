package internal

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestIsNilPointer(t *testing.T) {
	// Return an error for nil interfaces and nil pointers.
	qt.Assert(t, qt.IsNotNil(IsNilPointer(nil)))
	qt.Assert(t, qt.IsNotNil(IsNilPointer((*int)(nil))))

	// Return nil for non-pointers, even if they are zero values.
	qt.Assert(t, qt.IsNil(IsNilPointer(0)))
	qt.Assert(t, qt.IsNil(IsNilPointer("")))
	qt.Assert(t, qt.IsNil(IsNilPointer([]int(nil))))

	// Non-nil pointers are valid.
	qt.Assert(t, qt.IsNil(IsNilPointer(new(int))))
}
