package testutils

import (
	"fmt"
	"math/rand"
	"testing"
)

// TempBPFFS creates a random prefix to use when pinning on Windows.
func TempBPFFS(tb testing.TB) string {
	tb.Helper()

	// TODO(windows): this should use ebpf_get_next_pinned_program_path
	// or a generic equivalent to clean up.
	return fmt.Sprintf("ebpf-go-test/%d/", rand.Int())
}
