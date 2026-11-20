package sys

import (
	"testing"
	"unsafe"

	"github.com/go-quicktest/qt"
)

func TestCommonAttrLayout(t *testing.T) {
	var attr CommonAttr
	qt.Assert(t, qt.Equals(unsafe.Sizeof(attr), uintptr(24)))
	qt.Assert(t, qt.Equals(unsafe.Offsetof(attr.LogSize), uintptr(8)))
	qt.Assert(t, qt.Equals(unsafe.Offsetof(attr.LogLevel), uintptr(12)))
	qt.Assert(t, qt.Equals(unsafe.Offsetof(attr.LogTrueSize), uintptr(16)))
}
