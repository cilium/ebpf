package main

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const minimalSocketFilter = `__attribute__((section("socket"), used)) int main() { return 0; }`

func TestCompile(t *testing.T) {
	tmpFile := mustWriteTempFile(t, "test.c", minimalSocketFilter)

	var obj, dep bytes.Buffer
	err := compile(compileArgs{
		cc:   "clang",
		file: tmpFile,
		out:  &obj,
		dep:  &dep,
	})
	if err != nil {
		t.Fatal("Can't compile:", err)
	}

	if obj.Len() == 0 {
		t.Error("Compilation returns an empty result")
	}

	if dep.Len() == 0 {
		t.Error("Compilation doesn't generate depinfo")
	}
}

func TestReproducibleCompile(t *testing.T) {
	aFile := mustWriteTempFile(t, "test.c", minimalSocketFilter)
	bFile := mustWriteTempFile(t, "test.c", minimalSocketFilter)

	var a, b bytes.Buffer
	err := compile(compileArgs{
		cc:   "clang",
		file: aFile,
		out:  &a,
	})
	if err != nil {
		t.Fatal("Can't compile:", err)
	}

	err = compile(compileArgs{
		cc:   "clang",
		file: bFile,
		out:  &b,
	})
	if err != nil {
		t.Fatal("Can't compile:", err)
	}

	if !bytes.Equal(a.Bytes(), b.Bytes()) {
		t.Error("Compiling the same file twice doesn't give the same result")
	}
}

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

	output, err := adjustDependencies("/foo", want)
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

	if have := string(output); have != wantOutput {
		t.Logf("Have:\n%s", have)
		t.Logf("Want:\n%s", wantOutput)
		t.Error("Output doesn't match")
	}
}

func mustWriteTempFile(t *testing.T, name, contents string) string {
	t.Helper()

	tmp, err := ioutil.TempDir("", "bpf2go")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })

	tmpFile := filepath.Join(tmp, name)
	if err := ioutil.WriteFile(tmpFile, []byte(contents), 0660); err != nil {
		t.Fatal(err)
	}

	return tmpFile
}
