package sysenc

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestHasUnexportedFields(t *testing.T) {
	for _, test := range []struct {
		value  any
		result bool
	}{
		{struct{ A any }{}, false},
		{(*struct{ A any })(nil), false},
		{([]struct{ A any })(nil), false},
		{[1]struct{ A any }{}, false},
		{struct{ _ any }{}, false},
		{struct{ _ struct{ a any } }{}, true},
		{(*struct{ _ any })(nil), false},
		{([]struct{ _ any })(nil), false},
		{[1]struct{ _ any }{}, false},
		{struct{ a any }{}, true},
		{(*struct{ a any })(nil), true},
		{([]struct{ a any })(nil), true},
		{[1]struct{ a any }{}, true},
		{(*struct{ A []struct{ a any } })(nil), true},
		{(*struct{ A [1]struct{ a any } })(nil), true},
	} {
		t.Run(fmt.Sprintf("%T", test.value), func(t *testing.T) {
			have := hasUnexportedFields(reflect.TypeOf(test.value))
			qt.Assert(t, qt.Equals(have, test.result))
		})
	}
}
