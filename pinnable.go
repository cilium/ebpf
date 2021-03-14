package ebpf

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf/internal"
)

func pin(currentPath, newPath string, fd *internal.FD) error {
	if newPath == "" {
		return fmt.Errorf("pinned path cannot be empty")
	}
	if currentPath != "" {
		if currentPath == newPath {
			return nil
		}
		if err := os.Rename(currentPath, newPath); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("unable to pin the object at new path %v: %w", newPath, err)
			}
		} else {
			return nil
		}
	}
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
