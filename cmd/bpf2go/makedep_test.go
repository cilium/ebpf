//go:build !windows

package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestParseDependencies(t *testing.T) {
	const input = `main.go: /foo/bar baz

frob: /gobble \
 gubble

nothing:
`

	have, err := parseDependencies("/foo", strings.NewReader(input))
	if err != nil {
		t.Fatal("Can't parse dependencies:", err)
	}

	want := []dependency{
		{"/foo/main.go", []string{"/foo/bar", "/foo/baz"}},
		{"/foo/frob", []string{"/gobble", "/foo/gubble"}},
		{"/foo/nothing", nil},
	}

	if !reflect.DeepEqual(have, want) {
		t.Logf("Have: %#v", have)
		t.Logf("Want: %#v", want)
		t.Error("Result doesn't match")
	}

	var output bytes.Buffer
	err = adjustDependencies(&output, "/foo", want)
	if err != nil {
		t.Error("Can't adjust dependencies")
	}

	const wantOutput = `main.go: \
 bar \
 baz

frob: \
 ../gobble \
 gubble

nothing:

`

	if have := output.String(); have != wantOutput {
		t.Logf("Have:\n%s", have)
		t.Logf("Want:\n%s", wantOutput)
		t.Error("Output doesn't match")
	}
}
