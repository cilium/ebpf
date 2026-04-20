//go:build !windows

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// A single JSON Compilation Database entry.
// See https://clang.llvm.org/docs/JSONCompilationDatabase.html
type compdbEntry struct {
	Directory string   `json:"directory"`
	File      string   `json:"file"`
	Arguments []string `json:"arguments"`
}

// writeCompDB upserts entry into the compdb at path.
// Concurrent writers are serialised through a sibling `.lock` file.
// The file itself is replaced atomically via rename.
func writeCompDB(path string, entry compdbEntry) error {
	lock, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return fmt.Errorf("open compdb lock: %w", err)
	}
	defer lock.Close()

	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("lock compdb: %w", err)
	}

	var db []compdbEntry
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &db); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
	case errors.Is(err, fs.ErrNotExist):
		// new file
	default:
		return err
	}

	i := slices.IndexFunc(db, func(e compdbEntry) bool {
		return e.File == entry.File
	})
	if i >= 0 {
		db[i] = entry
	} else {
		db = append(db, entry)
	}

	slices.SortFunc(db, func(a, b compdbEntry) int {
		return strings.Compare(a.File, b.File)
	})

	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())

	enc := json.NewEncoder(tmp)
	enc.SetIndent("", "  ")
	if err := enc.Encode(db); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
