package testutils

import (
	"path/filepath"
	"testing"
)

// Files calls fn for each given file.
//
// The function errors out if the pattern matches no files.
func Files(t *testing.T, files []string, fn func(*testing.T, string)) {
	t.Helper()

	if len(files) == 0 {
		t.Fatalf("No files given")
	}

	for _, f := range files {
		file := f // force copy
		name := filepath.Base(file)
		t.Run(name, func(t *testing.T) {
			fn(t, file)
		})
	}
}

// Glob finds files matching a pattern.
//
// The pattern should may include full path. Excludes use the same syntax as
// pattern, but are only applied to the basename instead of the full path.
func Glob(tb testing.TB, pattern string, excludes ...string) []string {
	tb.Helper()

	files, err := filepath.Glob(pattern)
	if err != nil {
		tb.Fatal("Can't glob files:", err)
	}

	if len(excludes) == 0 {
		return files
	}

	var filtered []string
nextFile:
	for _, file := range files {
		base := filepath.Base(file)
		for _, exclude := range excludes {
			if matched, err := filepath.Match(exclude, base); err != nil {
				tb.Fatal(err)
			} else if matched {
				continue nextFile
			}
		}
		filtered = append(filtered, file)
	}

	return filtered
}
