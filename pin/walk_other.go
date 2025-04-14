//go:build !windows

package pin

import (
	"fmt"
	"io/fs"
	"iter"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/linux"
	"github.com/cilium/ebpf/internal/unix"
)

// WalkDir walks the file tree rooted at path and yields a [Pin] for each
// BPF object below the path.
//
// Callers must invoke [Pin.Take] if they wish to hold on to the object.
func WalkDir(root string, opts *ebpf.LoadPinOptions) iter.Seq2[*Pin, error] {
	return func(yield func(*Pin, error) bool) {
		fsType, err := linux.FSType(root)
		if err != nil {
			yield(nil, err)
			return
		}
		if fsType != unix.BPF_FS_MAGIC {
			yield(nil, fmt.Errorf("%s is not on a bpf filesystem", root))
			return
		}

		fn := func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			if d.IsDir() {
				return nil
			}

			path = filepath.Join(root, path)
			obj, err := Load(path, opts)
			if err != nil {
				return err
			}

			pin := &Pin{Path: path, Object: obj}
			defer pin.close()

			if !yield(pin, nil) {
				return fs.SkipAll
			}

			return nil
		}

		err = fs.WalkDir(os.DirFS(root), ".", fn)
		if err != nil {
			yield(nil, fmt.Errorf("walk: %w", err))
			return
		}
	}
}
