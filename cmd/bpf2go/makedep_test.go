package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/google/go-cmp/cmp"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestParseDependencies(t *testing.T) {
	const input = `main.go: /foo/bar baz

frob: /gobble \
 gubble

nothing:
`

	have, err := parseDependencies("/foo", strings.NewReader(input))
	testutils.SkipIfNotSupportedOnOS(t, err)
	if err != nil {
		t.Fatal("Can't parse dependencies:", err)
	}

	want := []dependency{
		{"/foo/main.go", []string{"/foo/bar", "/foo/baz"}},
		{"/foo/frob", []string{"/gobble", "/foo/gubble"}},
		{"/foo/nothing", nil},
	}

	qt.Assert(t, qt.CmpEquals(have, want, cmp.AllowUnexported(dependency{})))

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

	qt.Assert(t, qt.Equals(output.String(), wantOutput))
}
