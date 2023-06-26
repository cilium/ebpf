package sysenc

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

type struc struct {
	A uint64
	B uint32
}

func TestSizeOf(t *testing.T) {
	for _, test := range []struct {
		name   string
		value  any
		result int
		cached bool
	}{
		{
			"nil slice",
			([]byte)(nil),
			1,
			false,
		},
		{
			"slice size",
			[]uint32{1, 2},
			8,
			false,
		},
		{
			"pointer to slice",
			&[]uint32{1, 2},
			8,
			false,
		},
		{
			"array size",
			&[2]uint64{},
			16,
			false,
		},
		{
			"pointer to slice",
			&[]uint32{1},
			4,
			false,
		},
		{
			"explicit padding",
			&struct{ _ uint64 }{},
			8,
			true,
		},
	} {
		t.Run("valid: "+test.name, func(t *testing.T) {
			flushCachedSizes()
			qt.Assert(t, sizeOf(test.value), qt.Equals, test.result)
			qt.Assert(t, countCachedSizes() > 0, qt.Equals, test.cached)
		})
	}

	for _, test := range []struct {
		name   string
		value  any
		cached bool
	}{
		{
			"nil",
			nil,
			false,
		},
		{
			"nil pointer",
			(*uint64)(nil),
			false,
		},
		{
			"interspersed padding",
			&struct {
				B uint32
				A uint64
			}{},
			true,
		},
		{
			"trailing padding",
			&struc{},
			true,
		},
		{
			"padding between slice entries",
			&[]struc{},
			true,
		},
		{
			"padding between array entries",
			&[2]struc{},
			false,
		},
		{
			"unexported field",
			&struct{ a uint64 }{},
			true,
		},
		{
			"nil pointer to slice",
			(*[]byte)(nil),
			false,
		},
		{
			"struct containing pointer",
			&struct{ A *uint64 }{},
			true,
		},
	} {
		t.Run("invalid: "+test.name, func(t *testing.T) {
			flushCachedSizes()
			size := sizeOf(test.value)
			qt.Assert(t, size, qt.Equals, -1)
			qt.Assert(t, countCachedSizes() > 0, qt.Equals, test.cached)
		})
	}
}

func flushCachedSizes() {
	cachedSizes.Range(func(key, _ any) bool {
		cachedSizes.Delete(key)
		return true
	})
}

func countCachedSizes() (n int) {
	cachedSizes.Range(func(key, value any) bool {
		n++
		return true
	})
	return
}
