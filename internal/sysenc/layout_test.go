package sysenc

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"github.com/google/go-cmp/cmp"
)

type struc struct {
	A uint64
	B uint32
}

func TestLayoutOf(t *testing.T) {
	for _, test := range []struct {
		name   string
		value  any
		result dataLayout
		cached bool
	}{
		{
			"nil slice",
			([]byte)(nil),
			dataLayout{0, 1, 1},
			false,
		},
		{
			"trailing padding",
			&struc{},
			dataLayout{1, 8 + 4, 8 + 8},
			true,
		},
		{
			"slice size",
			[]uint32{1, 2},
			dataLayout{2, 4, 4},
			false,
		},
		{
			"pointer to slice",
			&[]uint32{1, 2},
			dataLayout{2, 4, 4},
			false,
		},
		{
			"array size",
			&[2]uint64{},
			dataLayout{2, 8, 8},
			false,
		},
		{
			"padding between slice entries",
			&[]struc{},
			dataLayout{0, 8 + 4, 8 + 8},
			true,
		},
		{
			"padding between array entries",
			&[2]struc{},
			dataLayout{2, 8 + 4, 8 + 8},
			false,
		},
		{
			"pointer to slice",
			&[]uint32{1},
			dataLayout{1, 4, 4},
			false,
		},
		{
			"explicit padding",
			&struct{ _ uint64 }{},
			dataLayout{1, 8, 8},
			true,
		},
	} {
		t.Run("valid: "+test.name, func(t *testing.T) {
			flushCachedLayouts()
			qt.Assert(t, layoutOf(test.value), qt.CmpEquals(cmp.AllowUnexported(dataLayout{})), test.result)
			qt.Assert(t, countCachedLayouts() > 0, qt.Equals, test.cached)
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
			flushCachedLayouts()
			layout := layoutOf(test.value)
			qt.Assert(t, layout.valid(), qt.IsFalse)
			qt.Assert(t, countCachedLayouts() > 0, qt.Equals, test.cached)
		})
	}
}

func flushCachedLayouts() {
	cachedLayouts.Range(func(key, _ any) bool {
		cachedLayouts.Delete(key)
		return true
	})
}

func countCachedLayouts() (n int) {
	cachedLayouts.Range(func(key, value any) bool {
		n++
		return true
	})
	return
}
