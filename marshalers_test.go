package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/internal"

	"github.com/go-quicktest/qt"
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
	qt.Assert(t, qt.DeepEquals(slice, expected))

	smallSlice := make([]uint32, possibleCPUs-1)
	qt.Assert(t, qt.IsNotNil(unmarshalPerCPUValue(smallSlice, elemLength, buf)))

	nilElemSlice := make([]*uint32, possibleCPUs)
	qt.Assert(t, qt.IsNotNil(unmarshalPerCPUValue(nilElemSlice, elemLength, buf)))
}
