//go:build linux

package testutils

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cilium/ebpf/internal/linux"
	"github.com/cilium/ebpf/internal/unix"
)

const testmod = "bpf_testmod"
const testmodFile = testmod + ".ko"

// RequireTestmod ensures bpf_testmod is loaded, skipping the test if it isn't
// available. reason describes what the test needs from the module.
func RequireTestmod(tb testing.TB, reason string) {
	tb.Helper()

	// bpf_testmod was introduced in Linux 5.11.
	SkipOnOldKernel(tb, "5.11", testmod)

	err := loadTestmod()
	if errors.Is(err, fs.ErrNotExist) {
		tb.Skipf("%s not available: %s (needed for %s)", testmod, err, reason)
	}
	if err != nil {
		tb.Fatalf("Load %s: %s", testmod, err)
	}
}

// loadTestmod inserts bpf_testmod from the running kernel's module directory,
// so that tests don't depend on a modprobe binary being present in user space.
//
// Returns an error wrapping [fs.ErrNotExist] if the module can't be found.
var loadTestmod = sync.OnceValue(func() error {
	if _, err := os.Stat(filepath.Join("/sys/module", testmod)); err == nil {
		return nil
	}

	release, err := linux.KernelRelease()
	if err != nil {
		return fmt.Errorf("get linux release: %w", err)
	}

	// Try /usr/lib first, since /lib is often a symlink to it.
	var path string
	for _, base := range []string{"/usr/lib/modules", "/lib/modules"} {
		path = findFile(filepath.Join(base, release), testmodFile)
		if path != "" {
			break
		}
	}
	if path == "" {
		return fmt.Errorf("finding %s for kernel %s: %w", testmodFile, release, fs.ErrNotExist)
	}

	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	err = unix.FinitModule(int(f.Fd()), "", 0)
	if err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("insert %s: %w", path, err)
	}

	return nil
})

// findFile recursively looks for name starting at root. Returns an empty string
// if no matching file was found.
func findFile(root, name string) string {
	var found string
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return fs.SkipDir
		}
		if !d.IsDir() && d.Name() == name {
			found = path
			return fs.SkipAll
		}
		return nil
	})
	return found
}
