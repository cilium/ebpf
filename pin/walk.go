package pin

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/linux"
	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/unix"
)

// WalkDirFunc is the type of the function called for each object visited by
// [WalkDir]. It's identical to [fs.WalkDirFunc], but with an extra [Pinner]
// argument. If the visited node is a directory, obj is nil.
//
// err contains any errors encountered during bpffs traversal or object loading.
type WalkDirFunc func(path string, d fs.DirEntry, obj Pinner, err error) error

// WalkDir walks the file tree rooted at path, calling bpffn for each node in
// the tree, including directories. Running WalkDir on a non-bpf filesystem is
// an error. Otherwise identical in behavior to [fs.WalkDir].
//
// See the [WalkDirFunc] for more information.
func WalkDir(root string, bpffn WalkDirFunc) error {
	if platform.IsWindows {
		return fmt.Errorf("walk bpffs: %w", internal.ErrNotSupportedOnOS)
	}

	fsType, err := linux.FSType(root)
	if err != nil {
		return err
	}
	if fsType != unix.BPF_FS_MAGIC {
		return fmt.Errorf("%s is not on a bpf filesystem", root)
	}

	fn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return bpffn(path, nil, nil, err)
		}

		if d.IsDir() {
			return bpffn(path, d, nil, err)
		}

		obj, err := Load(filepath.Join(root, path), nil)

		return bpffn(path, d, obj, err)
	}

	return fs.WalkDir(os.DirFS(root), ".", fn)
}
