package internal

import "testing"

func TestFSType(t *testing.T) {
	paths := []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}
	for _, p := range paths {
		fst, err := FSType(p)
		if err != nil {
			t.Fatalf("%s: %s", p, err)
		}
		if fst != TraceFSType {
			t.Fatalf("expected %x, got %x", TraceFSType, fst)
		}
	}
}
