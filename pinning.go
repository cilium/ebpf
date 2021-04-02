package ebpf

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf/internal"

	"golang.org/x/sys/unix"
)

func pin(currentPath, newPath string, fd *internal.FD) error {
	if newPath == "" {
		return errors.New("given pinning path cannot be empty")
	}
	if currentPath == "" {
		return internal.BPFObjPin(newPath, fd)
	}
	if currentPath == newPath {
		return nil
	}
	var err error
	// Object is now moved to the new pinning path.
	if err = unix.Renameat2(unix.AT_FDCWD, currentPath, unix.AT_FDCWD, newPath, unix.RENAME_NOREPLACE); err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("unable to move pinned object to new path %v: %w", newPath, err)
	}
	// Internal state not in sync with the file system so let's fix it.
	return internal.BPFObjPin(newPath, fd)
}

func unpin(pinnedPath string) error {
	if pinnedPath == "" {
		return nil
	}
	err := os.Remove(pinnedPath)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}
