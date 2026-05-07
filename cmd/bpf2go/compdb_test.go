//go:build !windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/go-quicktest/qt"
)

func readCompDB(tb testing.TB, path string) []compdbEntry {
	tb.Helper()
	data, err := os.ReadFile(path)
	qt.Assert(tb, qt.IsNil(err))
	var db []compdbEntry
	qt.Assert(tb, qt.IsNil(json.Unmarshal(data, &db)))
	return db
}

func TestCompDBCreate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compile_commands.json")

	entry := compdbEntry{
		Directory: "/tmp",
		File:      "/tmp/foo.c",
		Arguments: []string{"clang", "-c", "/tmp/foo.c"},
	}
	qt.Assert(t, qt.IsNil(writeCompDB(path, entry)))

	db := readCompDB(t, path)
	qt.Assert(t, qt.HasLen(db, 1))
	qt.Assert(t, qt.Equals(db[0].File, entry.File))
	qt.Assert(t, qt.DeepEquals(db[0].Arguments, entry.Arguments))
}

func TestCompDBUpsert(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compile_commands.json")

	a1 := compdbEntry{Directory: "/tmp", File: "/tmp/a.c", Arguments: []string{"clang", "old"}}
	b := compdbEntry{Directory: "/tmp", File: "/tmp/b.c", Arguments: []string{"clang", "b"}}
	a2 := compdbEntry{Directory: "/tmp", File: "/tmp/a.c", Arguments: []string{"clang", "new"}}

	qt.Assert(t, qt.IsNil(writeCompDB(path, a1)))
	qt.Assert(t, qt.IsNil(writeCompDB(path, b)))
	qt.Assert(t, qt.IsNil(writeCompDB(path, a2)))

	db := readCompDB(t, path)
	qt.Assert(t, qt.HasLen(db, 2))
	for _, e := range db {
		if e.File == "/tmp/a.c" {
			qt.Check(t, qt.DeepEquals(e.Arguments, []string{"clang", "new"}))
		}
	}
}

func TestCompDBSorted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compile_commands.json")

	for _, name := range []string{"/tmp/z.c", "/tmp/a.c", "/tmp/m.c"} {
		qt.Assert(t, qt.IsNil(writeCompDB(path, compdbEntry{
			Directory: "/tmp", File: name, Arguments: []string{"clang"},
		})))
	}

	db := readCompDB(t, path)
	qt.Assert(t, qt.HasLen(db, 3))
	qt.Check(t, qt.Equals(db[0].File, "/tmp/a.c"))
	qt.Check(t, qt.Equals(db[1].File, "/tmp/m.c"))
	qt.Check(t, qt.Equals(db[2].File, "/tmp/z.c"))
}

func TestCompDBConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compile_commands.json")

	const n = 16
	errs := make(chan error, n)
	var wg sync.WaitGroup
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			errs <- writeCompDB(path, compdbEntry{
				Directory: "/tmp",
				File:      fmt.Sprintf("/tmp/f%02d.c", i),
				Arguments: []string{"clang"},
			})
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		qt.Check(t, qt.IsNil(err))
	}

	db := readCompDB(t, path)
	qt.Assert(t, qt.HasLen(db, n))
}

func TestCompDBMalformedExisting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "compile_commands.json")
	qt.Assert(t, qt.IsNil(os.WriteFile(path, []byte("{not json"), 0644)))

	err := writeCompDB(path, compdbEntry{
		Directory: "/tmp", File: "/tmp/a.c", Arguments: []string{"clang"},
	})
	qt.Assert(t, qt.IsNotNil(err))

	data, rerr := os.ReadFile(path)
	qt.Assert(t, qt.IsNil(rerr))
	qt.Assert(t, qt.Equals(string(data), "{not json"))
}
