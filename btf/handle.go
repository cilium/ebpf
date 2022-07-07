package btf

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf/internal/sys"
)

// HandleIterator allows enumerating BTF blobs loaded into the kernel.
type HandleIterator struct {
	id  ID
	err error
}

func NewHandleIterator() *HandleIterator {
	return &HandleIterator{0, nil}
}

// Next retrieves a handle for the next BTF blob.
//
// [Handle.Close] is called if *handle is non-nil to avoid leaking fds.
//
// Returns true if another BTF blob was found. Call [HandleIterator.Err] after
// the function returns false.
func (it *HandleIterator) Next(handle **Handle) bool {
	if *handle != nil {
		(*handle).Close()
	}

	for {
		attr := &sys.BtfGetNextIdAttr{Id: it.id}
		err := sys.BtfGetNextId(attr)
		if errors.Is(err, os.ErrNotExist) {
			// There are no more BTF objects.
			return false
		} else if err != nil {
			it.err = fmt.Errorf("get next BTF ID: %w", err)
			return false
		}

		it.id = attr.NextId
		*handle, err = NewHandleFromID(it.id)
		if errors.Is(err, os.ErrNotExist) {
			// Try again with the next ID.
			continue
		} else if err != nil {
			it.err = fmt.Errorf("retrieve handle for ID %d: %w", it.id, err)
			return false
		}

		return true
	}
}

// Err returns an error if iteration failed for some reason.
func (it *HandleIterator) Err() error {
	return it.err
}
