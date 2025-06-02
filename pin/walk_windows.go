package pin

import (
	"errors"
	"fmt"
	"iter"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/efw"
)

// WalkDir walks the file tree rooted at path and yields a [Pin] for each
// BPF object below the path.
//
// Callers must invoke [Pin.Take] if they wish to hold on to the object.
func WalkDir(root string, opts *ebpf.LoadPinOptions) iter.Seq2[*Pin, error] {
	return func(yield func(*Pin, error) bool) {
		root, err := efw.EbpfCanonicalizePinPath(root)
		if err != nil {
			yield(nil, fmt.Errorf("failed to canonicalize pin path %q: %w", root, err))
			return
		}

		cursor := root
		for {
			next, _, err := efw.EbpfGetNextPinnedObjectPath(cursor, efw.EBPF_OBJECT_UNKNOWN)
			if errors.Is(err, efw.EBPF_NO_MORE_KEYS) {
				break
			} else if err != nil {
				yield(nil, err)
				return
			}

			if !strings.HasPrefix(next, root) {
				break
			}

			obj, err := Load(next, opts)
			if err != nil {
				yield(nil, err)
				return
			}

			pin := &Pin{next, obj}
			ok := yield(pin, nil)
			pin.close()
			if !ok {
				return
			}

			cursor = next
		}
	}
}
