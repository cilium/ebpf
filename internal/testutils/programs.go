package testutils

import (
	"fmt"
	"os"
	"testing"
)

func ClangBin(tb testing.TB) string {
	tb.Helper()

	if testing.Short() {
		tb.Skip("Not compiling with -short")
	}

	// Use a floating clang version for local development, but allow CI to run
	// against oldest supported clang.
	clang := "clang"
	if minVersion := os.Getenv("CI_MIN_CLANG_VERSION"); minVersion != "" {
		clang = fmt.Sprintf("clang-%s", minVersion)
	}

	tb.Log("Testing against", clang)
	return clang
}
