package sysenc_test

import (
	"testing"
	"unsafe"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/sysenc"
)

func TestZeroBuffer(t *testing.T) {
	var zero sysenc.Buffer

	qt.Assert(t, qt.Equals(zero.CopyTo(make([]byte, 1)), 0))
	qt.Assert(t, qt.Equals(zero.Pointer(), sys.Pointer{}))
	qt.Assert(t, qt.IsNotNil(zero.Unmarshal(new(uint16))))
}

func TestUnsafeBuffer(t *testing.T) {
	ptr := unsafe.Pointer(new(uint16))
	buf := sysenc.UnsafeBuffer(ptr)

	qt.Assert(t, qt.Equals(buf.CopyTo(make([]byte, 1)), 0))
	qt.Assert(t, qt.Equals(buf.Pointer(), sys.NewPointer(ptr)))
	qt.Assert(t, qt.IsNil(buf.Unmarshal(new(uint16))))
}
