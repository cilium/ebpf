//go:build !windows

package gen

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

const (
	func1 = `__attribute__((section("socket"), used)) int func1() { return 1; }`
	func2 = `__attribute__((section("socket"), used)) int func2() { return 2; }`
)

func TestLink(t *testing.T) {
	if testing.Short() {
		t.SkipNow()
	}

	dir := t.TempDir()
	mustWriteFile(t, dir, "func1.c", func1)
	mustWriteFile(t, dir, "func2.c", func2)

	// Compile first object
	obj1 := filepath.Join(dir, "func1.o")
	err := Compile(CompileArgs{
		CC:               testutils.ClangBin(t),
		DisableStripping: true,
		Workdir:          dir,
		Source:           filepath.Join(dir, "func1.c"),
		Dest:             obj1,
	})
	if err != nil {
		t.Fatal("Can't compile func1:", err)
	}

	// Compile second object
	obj2 := filepath.Join(dir, "func2.o")
	err = Compile(CompileArgs{
		CC:               testutils.ClangBin(t),
		DisableStripping: true,
		Workdir:          dir,
		Source:           filepath.Join(dir, "func2.c"),
		Dest:             obj2,
	})
	if err != nil {
		t.Fatal("Can't compile func2:", err)
	}

	// Link both objects
	linked := filepath.Join(dir, "linked.o")
	err = Link(LinkArgs{
		Dest:    linked,
		Sources: []string{obj1, obj2},
	})
	if err != nil {
		t.Fatal("Can't link objects:", err)
	}

	// Verify the linked file exists and has content
	stat, err := os.Stat(linked)
	if err != nil {
		t.Fatal("Can't stat linked file:", err)
	}

	if stat.Size() == 0 {
		t.Error("Linked file is empty")
	}
}
