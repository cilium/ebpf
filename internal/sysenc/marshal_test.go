package sysenc

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"reflect"
	"testing"

	"github.com/cilium/ebpf/internal"
	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp/cmpopts"
)

type testcase struct {
	new        func() any
	zeroAllocs bool
}

type explicitPad struct {
	_ uint32
}

func testcases() []testcase {
	return []testcase{
		{func() any { return new([1]uint64) }, true},
		{func() any { return new(int16) }, true},
		{func() any { return new(uint16) }, true},
		{func() any { return new(int32) }, true},
		{func() any { return new(uint32) }, true},
		{func() any { return new(int64) }, true},
		{func() any { return new(uint64) }, true},
		{func() any { return make([]byte, 9) }, true},
		{func() any { return new(struc) }, true},
		{func() any { return make([]struc, 0) }, false},
		{func() any { return make([]struc, 1) }, false},
		{func() any { return make([]struc, 2) }, false},
		{func() any { return new(explicitPad) }, false},
		{func() any { return int16(math.MaxInt16) }, false},
		{func() any { return uint16(math.MaxUint16) }, false},
		{func() any { return int32(math.MaxInt32) }, false},
		{func() any { return uint32(math.MaxUint32) }, false},
		{func() any { return int64(math.MaxInt64) }, false},
		{func() any { return uint64(math.MaxUint64) }, false},
		{func() any { return struc{math.MaxUint64, math.MaxUint32} }, false},
	}
}

func TestMarshal(t *testing.T) {
	for _, test := range testcases() {
		value := test.new()
		t.Run(fmt.Sprintf("%T", value), func(t *testing.T) {
			var want bytes.Buffer
			if err := binary.Write(&want, internal.NativeEndian, value); err != nil {
				t.Fatal(err)
			}

			have := make([]byte, want.Len())
			buf, err := Marshal(value, binary.Size(value))
			if err != nil {
				t.Fatal(err)
			}
			qt.Assert(t, buf.Copy(have), qt.Equals, want.Len())
			qt.Assert(t, have, qt.CmpEquals(cmpopts.EquateEmpty()), want.Bytes())
		})
	}
}

func TestMarshalAllocations(t *testing.T) {
	allocationsPerMarshal := func(t *testing.T, data any) float64 {
		size := binary.Size(data)
		return testing.AllocsPerRun(5, func() {
			_, err := Marshal(data, size)
			if err != nil {
				t.Fatal(err)
			}
		})
	}

	for _, test := range testcases() {
		if !test.zeroAllocs {
			continue
		}

		value := test.new()
		t.Run(fmt.Sprintf("%T", value), func(t *testing.T) {
			qt.Assert(t, allocationsPerMarshal(t, value), qt.Equals, float64(0))
		})
	}
}

func TestUnmarshal(t *testing.T) {
	for _, test := range testcases() {
		value := test.new()
		if !canUnmarshalInto(value) {
			continue
		}

		t.Run(fmt.Sprintf("%T", value), func(t *testing.T) {
			want := test.new()
			buf := randomiseValue(t, want)

			qt.Assert(t, Unmarshal(value, buf), qt.IsNil)
			qt.Assert(t, value, qt.DeepEquals, want)
		})
	}
}

func TestUnmarshalAllocations(t *testing.T) {
	allocationsPerUnmarshal := func(t *testing.T, data any, buf []byte) float64 {
		return testing.AllocsPerRun(5, func() {
			err := Unmarshal(data, buf)
			if err != nil {
				t.Fatal(err)
			}
		})
	}

	for _, test := range testcases() {
		if !test.zeroAllocs {
			continue
		}

		value := test.new()
		if !canUnmarshalInto(value) {
			continue
		}

		t.Run(fmt.Sprintf("%T", value), func(t *testing.T) {
			buf := make([]byte, binary.Size(value))
			qt.Assert(t, allocationsPerUnmarshal(t, value, buf), qt.Equals, float64(0))
		})
	}
}

func BenchmarkMarshal(b *testing.B) {
	for _, test := range testcases() {
		value := test.new()
		b.Run(fmt.Sprintf("%T", value), func(b *testing.B) {
			size := binary.Size(value)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				Marshal(value, size)
			}
		})
	}
}

func BenchmarkUnmarshal(b *testing.B) {
	for _, test := range testcases() {
		value := test.new()
		if !canUnmarshalInto(value) {
			continue
		}

		b.Run(fmt.Sprintf("%T", value), func(b *testing.B) {
			size := binary.Size(value)
			buf := make([]byte, size)
			b.ResetTimer()
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				Unmarshal(value, buf)
			}
		})
	}
}

func randomiseValue(tb testing.TB, value any) []byte {
	tb.Helper()

	size := binary.Size(value)
	if size == -1 {
		tb.Fatalf("Can't unmarshal into %T", value)
	}

	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte(i)
	}

	err := binary.Read(bytes.NewReader(buf), internal.NativeEndian, value)
	qt.Assert(tb, err, qt.IsNil)

	return buf
}

func canUnmarshalInto(data any) bool {
	kind := reflect.TypeOf(data).Kind()
	return kind == reflect.Slice || kind == reflect.Pointer
}
