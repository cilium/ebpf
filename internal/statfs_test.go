package internal

import (
	"testing"

	"github.com/cilium/ebpf/internal/unix"
)

func TestFSType(t *testing.T) {
	paths := []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}
	for _, p := range paths {
		fst, err := FSType(p)
		if err != nil {
			t.Fatalf("%s: %s", p, err)
		}
		if fst != unix.TRACEFS_MAGIC {
			t.Fatalf("expected %x, got %x", unix.TRACEFS_MAGIC, fst)
		}
	}
}
