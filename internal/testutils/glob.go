package testutils

import (
	"path/filepath"
	"testing"
)

// TestFiles calls fn for each file matching pattern.
//
// The function errors out if the pattern matches no files.
func TestFiles(t *testing.T, pattern string, fn func(*testing.T, string)) {
	t.Helper()

	files, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal("Can't glob files:", err)
	}

	if len(files) == 0 {
		t.Fatalf("Pattern %s matched no files", pattern)
	}

	for _, f := range files {
		file := f // force copy
		name := filepath.Base(file)
		t.Run(name, func(t *testing.T) {
			fn(t, file)
		})
	}
}
