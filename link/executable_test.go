package link

import (
	"errors"
	"testing"
)

var bashEx, _ = Executable("/bin/bash")

func TestExecutable(t *testing.T) {
	_, err := Executable("")
	if err == nil {
		t.Fatal("create executable: expected error on empty path")
	}

	if bashEx.path != "/bin/bash" {
		t.Fatalf("create executable: unexpected path '%s'", bashEx.path)
	}

	sym, err := bashEx.symbol("readline")
	if err != nil {
		t.Fatalf("find symbol: %v", err)
	}
	if sym.Name != "readline" {
		t.Fatalf("find symbol: unexpected symbol '%s'", sym.Name)
	}

	_, err = bashEx.symbol("bogus")
	if !errors.Is(err, ErrSymbolNotFound) {
		t.Fatalf("find symbol: unexpected error: %v", err)
	}
}
