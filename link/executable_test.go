package link

import (
	"errors"
	"testing"
)

func TestExecutable(t *testing.T) {
	_, err := Executable("")
	if err == nil {
		t.Fatal("create executable: expected error on empty path")
	}

	ex, err := Executable("/bin/ls")
	if err != nil {
		t.Fatalf("create executable: %v", err)
	}
	if ex.path != "/bin/ls" {
		t.Fatalf("create executable: unexpected path '%s'", ex.path)
	}
}

func TestExecutableFindSymbol(t *testing.T) {
	ex, err := Executable("/bin/ls")
	if err != nil {
		t.Fatalf("create executable: %v", err)
	}

	sym, err := ex.symbolByName("getenv")
	if err != nil {
		t.Fatalf("find symbol: %v", err)
	}
	if sym.Name != "getenv" {
		t.Fatalf("find symbol: unexpected symbol '%s'", sym.Name)
	}

	_, err = ex.symbolByName("bogus")
	if !errors.Is(err, ErrSymbolNotFound) {
		t.Fatalf("find symbol: unexpected error: %v", err)
	}
}
