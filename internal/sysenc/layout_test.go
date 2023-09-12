package sysenc

import (
	"fmt"
	"reflect"
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestHasUnexportedFields(t *testing.T) {
	for _, test := range []struct {
		value  any
		result bool
	}{
		{struct{ A any }{}, false},
		{(*struct{ A any })(nil), false},
		{([]struct{ A any })(nil), false},
		{struct{ _ any }{}, false},
		{struct{ _ struct{ a any } }{}, true},
		{(*struct{ _ any })(nil), false},
		{([]struct{ _ any })(nil), false},
		{struct{ a any }{}, true},
		{(*struct{ a any })(nil), true},
		{([]struct{ a any })(nil), true},
		{(*struct{ A []struct{ a any } })(nil), true},
	} {
		t.Run(fmt.Sprintf("%T", test.value), func(t *testing.T) {
			have := hasUnexportedFields(reflect.TypeOf(test.value))
			qt.Assert(t, have, qt.Equals, test.result)
		})
	}
}
