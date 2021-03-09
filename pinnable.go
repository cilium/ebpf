package ebpf

import (
	"fmt"
	"os"

	"github.com/cilium/ebpf/internal"
)

type pinnable interface {
	getFD() *internal.FD
	getPinnedPath() string
	setPinnedPath(path string)
	IsPinned() bool
}

func pin(fileName string, pinnable pinnable) error {
	if fileName == "" {
		return fmt.Errorf("pinned path cannot be empty")
	}
	if pinnable.IsPinned() {
		path := pinnable.getPinnedPath()
		if path == fileName {
			return nil
		}
		if err := os.Rename(path, fileName); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("unable to pin the map at new path %v: %w", fileName, err)
			}
		} else {
			pinnable.setPinnedPath(path)
			return nil
		}
	}
	err := internal.BPFObjPin(fileName, pinnable.getFD())
	if err == nil {
		pinnable.setPinnedPath(fileName)
	}
	return err
}

func unpin(pinnable pinnable) error {
	path := pinnable.getPinnedPath()
	if path == "" {
		return nil
	}
	err := os.Remove(path)
	if err == nil || os.IsNotExist(err) {
		pinnable.setPinnedPath("")
		return nil
	}
	return err
}
