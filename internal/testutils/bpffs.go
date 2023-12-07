package testutils

import (
	"os"
	"testing"
)

// TempBPFFS creates a temporary directory on a BPF FS.
//
// The directory is automatically cleaned up at the end of the test run.
func TempBPFFS(tb testing.TB) string {
	tb.Helper()

	tmp, err := os.MkdirTemp("/sys/fs/bpf", "ebpf-test")
	if err != nil {
		tb.Fatal("Create temporary directory on BPFFS:", err)
	}
	tb.Cleanup(func() { os.RemoveAll(tmp) })

	return tmp
}
