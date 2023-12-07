package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const minimalSocketFilter = `__attribute__((section("socket"), used)) int main() { return 0; }`

func TestCompile(t *testing.T) {
	dir := mustWriteTempFile(t, "test.c", minimalSocketFilter)

	var dep bytes.Buffer
	err := compile(compileArgs{
		cc:     clangBin(t),
		dir:    dir,
		source: filepath.Join(dir, "test.c"),
		dest:   filepath.Join(dir, "test.o"),
		dep:    &dep,
	})
	if err != nil {
		t.Fatal("Can't compile:", err)
	}

	stat, err := os.Stat(filepath.Join(dir, "test.o"))
	if err != nil {
		t.Fatal("Can't stat output:", err)
	}

	if stat.Size() == 0 {
		t.Error("Compilation creates an empty file")
	}

	if dep.Len() == 0 {
		t.Error("Compilation doesn't generate depinfo")
	}

	if _, err := parseDependencies(dir, &dep); err != nil {
		t.Error("Can't parse dependencies:", err)
	}
}

func TestReproducibleCompile(t *testing.T) {
	clangBin := clangBin(t)
	dir := mustWriteTempFile(t, "test.c", minimalSocketFilter)

	err := compile(compileArgs{
		cc:     clangBin,
		dir:    dir,
		source: filepath.Join(dir, "test.c"),
		dest:   filepath.Join(dir, "a.o"),
	})
	if err != nil {
		t.Fatal("Can't compile:", err)
	}

	err = compile(compileArgs{
		cc:     clangBin,
		dir:    dir,
		source: filepath.Join(dir, "test.c"),
		dest:   filepath.Join(dir, "b.o"),
	})
	if err != nil {
		t.Fatal("Can't compile:", err)
	}

	aBytes, err := os.ReadFile(filepath.Join(dir, "a.o"))
	if err != nil {
		t.Fatal(err)
	}

	bBytes, err := os.ReadFile(filepath.Join(dir, "b.o"))
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aBytes, bBytes) {
		t.Error("Compiling the same file twice doesn't give the same result")
	}
}

func TestTriggerMissingTarget(t *testing.T) {
	dir := mustWriteTempFile(t, "test.c", `_Pragma(__BPF_TARGET_MISSING);`)

	err := compile(compileArgs{
		cc:     clangBin(t),
		dir:    dir,
		source: filepath.Join(dir, "test.c"),
		dest:   filepath.Join(dir, "a.o"),
	})

	if err == nil {
		t.Fatal("No error when compiling __BPF_TARGET_MISSING")
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

	tmp, err := os.MkdirTemp("", "bpf2go")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })

	tmpFile := filepath.Join(tmp, name)
	if err := os.WriteFile(tmpFile, []byte(contents), 0660); err != nil {
		t.Fatal(err)
	}

	return tmp
}
