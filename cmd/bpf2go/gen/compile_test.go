//go:build !windows

package gen

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

const minimalSocketFilter = `__attribute__((section("socket"), used)) int main() { return 0; }`

func TestCompile(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	dir := t.TempDir()
	mustWriteFile(t, dir, "test.c", minimalSocketFilter)

	err := Compile(CompileArgs{
		CC:               testutils.ClangBin(t),
		DisableStripping: true,
		Workdir:          dir,
		Source:           filepath.Join(dir, "test.c"),
		Dest:             filepath.Join(dir, "test.o"),
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
}

func TestReproducibleCompile(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	clangBin := testutils.ClangBin(t)
	dir := t.TempDir()
	mustWriteFile(t, dir, "test.c", minimalSocketFilter)

	err := Compile(CompileArgs{
		CC:               clangBin,
		DisableStripping: true,
		Workdir:          dir,
		Source:           filepath.Join(dir, "test.c"),
		Dest:             filepath.Join(dir, "a.o"),
	})
	if err != nil {
		t.Fatal("Can't compile:", err)
	}

	err = Compile(CompileArgs{
		CC:               clangBin,
		DisableStripping: true,
		Workdir:          dir,
		Source:           filepath.Join(dir, "test.c"),
		Dest:             filepath.Join(dir, "b.o"),
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
	if testing.Short() {
		t.SkipNow()
	}

	dir := t.TempDir()
	mustWriteFile(t, dir, "test.c", `_Pragma(__BPF_TARGET_MISSING);`)

	err := Compile(CompileArgs{
		CC:      testutils.ClangBin(t),
		Workdir: dir,
		Source:  filepath.Join(dir, "test.c"),
		Dest:    filepath.Join(dir, "a.o"),
	})

	if err == nil {
		t.Fatal("No error when compiling __BPF_TARGET_MISSING")
	}
}

func mustWriteFile(tb testing.TB, dir, name, contents string) {
	tb.Helper()
	tmpFile := filepath.Join(dir, name)
	if err := os.WriteFile(tmpFile, []byte(contents), 0660); err != nil {
		tb.Fatal(err)
	}
}
