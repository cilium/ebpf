package sysenc_test

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/sysenc"
	qt "github.com/frankban/quicktest"
)

func TestZeroBuffer(t *testing.T) {
	var zero sysenc.Buffer

	qt.Assert(t, zero.CopyTo(make([]byte, 1)), qt.Equals, 0)
	qt.Assert(t, zero.Pointer(), qt.Equals, sys.Pointer{})
	qt.Assert(t, zero.Unmarshal(new(uint16)), qt.IsNotNil)
}

func TestUnsafeBuffer(t *testing.T) {
	ptr := unsafe.Pointer(new(uint16))
	buf := sysenc.UnsafeBuffer(ptr)

	qt.Assert(t, buf.CopyTo(make([]byte, 1)), qt.Equals, 0)
	qt.Assert(t, buf.Pointer(), qt.Equals, sys.NewPointer(ptr))
	qt.Assert(t, buf.Unmarshal(new(uint16)), qt.IsNil)
}
