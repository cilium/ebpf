package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/internal"
	qt "github.com/frankban/quicktest"
)

func TestUnmarshalPerCPUValue(t *testing.T) {
	possibleCPUs := MustPossibleCPU()
	expected := make([]uint32, possibleCPUs)
	for i := 0; i < possibleCPUs; i++ {
		expected[i] = uint32(1021 * (i + 1))
	}
	elemLength := 4

	buf := make([]byte, possibleCPUs*internal.Align(elemLength, 8))
	b := buf
	for _, elem := range expected {
		internal.NativeEndian.PutUint32(b, elem)
		b = b[8:]
	}
	slice := make([]uint32, possibleCPUs)
	err := unmarshalPerCPUValue(slice, elemLength, buf)
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, slice, qt.DeepEquals, expected)

	smallSlice := make([]uint32, possibleCPUs-1)

	err = unmarshalPerCPUValue(smallSlice, elemLength, buf)
	if err == nil {
		t.Fatal("expected error")
	}
}
