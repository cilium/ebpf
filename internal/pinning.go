package internal

import (
	"errors"
	"fmt"
	"os"
)

func Pin(currentPath, newPath string, fd *FD) error {
	if newPath == "" {
		return errors.New("given pinning path cannot be empty")
	}
	if currentPath == newPath {
		return nil
	}
	if currentPath == "" {
		return BPFObjPin(newPath, fd)
	}
	var err error
	// Object is now moved to the new pinning path.
	if err = os.Rename(currentPath, newPath); err == nil {
		return nil
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("unable to move pinned object to new path %v: %w", newPath, err)
	}
	// Internal state not in sync with the file system so let's fix it.
	return BPFObjPin(newPath, fd)
}

func Unpin(pinnedPath string) error {
	if pinnedPath == "" {
		return nil
	}
	err := os.Remove(pinnedPath)
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}
