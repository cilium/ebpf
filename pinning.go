package ebpf

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
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
	if err = os.Rename(currentPath, newPath); err == nil {
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

// LoadPinOptions control how a pinned object is loaded.
type LoadPinOptions struct {
	// Request a read-only or write-only object. The default is a read-write
	// object. Only one of the flags may be set.
	ReadOnly  bool
	WriteOnly bool

	// Raw flags for the syscall. Other fields of this struct take precedence.
	Flags uint32
}

func loadPinFlags(opts *LoadPinOptions) uint32 {
	if opts == nil {
		return 0
	}

	flags := opts.Flags
	if opts.ReadOnly {
		flags |= unix.BPF_F_RDONLY
	}
	if opts.WriteOnly {
		flags |= unix.BPF_F_WRONLY
	}
	return flags
}
