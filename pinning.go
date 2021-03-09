package ebpf

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf/internal"
)

func pin(currentPath, newPath string, fd *internal.FD) error {
	var err error
	if currentPath == "" {
		return internal.BPFObjPin(newPath, fd)
	}
	if newPath == "" {
		return errors.New("new pinned path cannot be empty")
	}
	if currentPath == newPath {
		return nil
	}
	if err = os.Rename(currentPath, newPath); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("unable to move pinned object to new path %v: %w", newPath, err)
		} else {
			return internal.BPFObjPin(newPath, fd)
		}
	}
	return nil
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
