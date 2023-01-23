package internal

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestIdentifier(t *testing.T) {
	testcases := []struct {
		in, out string
	}{
		{".rodata", "Rodata"},
		{"_foo_bar_", "FooBar"},
		{"ipv6_test", "Ipv6Test"},
		{"FOO_BAR", "FOO_BAR"},
		{"FOO_", "FOO_"},
		{"FOO__BAR", "FOO__BAR"},
		{"FOO___BAR", "FOO___BAR"},
		{"_FOO__BAR", "FOO__BAR"},
		{"__FOO__BAR", "FOO__BAR"},
	}

	for _, tc := range testcases {
		have := Identifier(tc.in)
		if have != tc.out {
			t.Errorf("Expected %q as output of %q, got %q", tc.out, tc.in, have)
		}
	}
}

func TestGoTypeName(t *testing.T) {
	type foo struct{}
	type bar[T any] struct{}
	qt.Assert(t, GoTypeName(foo{}), qt.Equals, "foo")
	qt.Assert(t, GoTypeName(new(foo)), qt.Equals, "foo")
	qt.Assert(t, GoTypeName(new(*foo)), qt.Equals, "foo")
	qt.Assert(t, GoTypeName(bar[int]{}), qt.Equals, "bar[int]")
	// Broken in the stdlib, see GoTypeName for details.
	// qt.Assert(t, GoTypeName(bar[qt.C]{}), qt.Equals, "bar[quicktest.C]")
}
