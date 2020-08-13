package main

import (
	"testing"
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
		have := identifier(tc.in)
		if have != tc.out {
			t.Errorf("Expected %q as output of %q, got %q", tc.out, tc.in, have)
		}
	}
}
