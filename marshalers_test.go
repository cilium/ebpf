package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/internal"

	"github.com/go-quicktest/qt"
)

func TestMarshalUnmarshalBatchPerCPUValue(t *testing.T) {
	const (
		batchLen   = 3
		elemLength = 4
	)
	possibleCPU := MustPossibleCPU()
	sliceLen := batchLen * possibleCPU
	slice := makeFilledSlice(sliceLen)
	buf, err := marshalBatchPerCPUValue(slice, batchLen, elemLength)
	if err != nil {
		t.Fatal(err)
	}
	output := make([]uint32, sliceLen)
	err = unmarshalBatchPerCPUValue(output, batchLen, elemLength, buf)
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, qt.DeepEquals(output, slice))
}

func TestMarshalBatchPerCPUValue(t *testing.T) {
	const (
		batchLen   = 3
		elemLength = 4
	)
	possibleCPU := MustPossibleCPU()
	sliceLen := batchLen * possibleCPU
	slice := makeFilledSlice(sliceLen)
	expected := make([]byte, sliceLen*internal.Align(elemLength, 8))
	b := expected
	for _, elem := range slice {
		internal.NativeEndian.PutUint32(b, elem)
		b = b[8:]
	}
	buf, err := marshalBatchPerCPUValue(slice, batchLen, elemLength)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(buf, expected))

	tooSmall := slice[:len(slice)-1]
	buf, err = marshalBatchPerCPUValue(tooSmall, batchLen, elemLength)
	qt.Assert(t, qt.IsNotNil(err))
	qt.Assert(t, qt.HasLen(buf, 0))

	tooBig := append(slice, 0)
	buf, err = marshalBatchPerCPUValue(tooBig, batchLen, elemLength)
	qt.Assert(t, qt.IsNotNil(err))
	qt.Assert(t, qt.HasLen(buf, 0))
}

func TestUnmarshalBatchPerCPUValue(t *testing.T) {
	const (
		batchLen   = 3
		elemLength = 4
	)
	possibleCPU := MustPossibleCPU()
	outputLen := batchLen * possibleCPU
	output := make([]uint32, outputLen)
	expected := makeFilledSlice(batchLen * possibleCPU)

	buf := make([]byte, batchLen*possibleCPU*internal.Align(elemLength, 8))
	b := buf
	for _, elem := range expected {
		internal.NativeEndian.PutUint32(b, elem)
		b = b[8:]
	}
	err := unmarshalBatchPerCPUValue(output, batchLen, elemLength, buf)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.DeepEquals(output, expected))

	tooSmall := make([]uint32, outputLen-1)
	err = unmarshalBatchPerCPUValue(tooSmall, batchLen, elemLength, buf)
	qt.Assert(t, qt.IsNotNil(err))

	tooBig := make([]uint32, outputLen+1)
	err = unmarshalBatchPerCPUValue(tooBig, batchLen, elemLength, buf)
	qt.Assert(t, qt.IsNotNil(err))

	empty := make([]uint32, outputLen)
	tooSmallBuf := buf[:len(buf)-1]
	err = unmarshalBatchPerCPUValue(empty, batchLen, elemLength, tooSmallBuf)
	qt.Assert(t, qt.IsNotNil(err))

	tooBigBuf := append(buf, 0)
	err = unmarshalBatchPerCPUValue(empty, batchLen, elemLength, tooBigBuf)
	qt.Assert(t, qt.IsNotNil(err))
}

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

func makeFilledSlice(len int) []uint32 {
	slice := make([]uint32, len)
	for i := range slice {
		slice[i] = uint32(1021 * (i + 1))
	}
	return slice
}
