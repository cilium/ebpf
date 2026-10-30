package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/internal/sys"
)

// operationError snapshots a message while retaining the immediate cause, like
// fmt.Errorf with one %w. Known syscall errors don't need fmt's shared buffers.
type operationError struct {
	message string
	cause   error
}

func (e *operationError) Error() string { return e.message }
func (e *operationError) Unwrap() error { return e.cause }

func wrapOperationError(prefix string, err error) error {
	if message, ok := sys.ErrnoMessage(err); ok {
		return &operationError{prefix + message, err}
	}
	switch err {
	case sysErrKeyNotExist, sysErrKeyExist, sysErrNotSupported:
		return &operationError{prefix + err.Error(), err}
	}
	if e, ok := err.(*operationError); ok && e != nil {
		return &operationError{prefix + e.message, err}
	}
	// Foreign errors may implement fmt.Formatter or panic in Error. Keep fmt's
	// formatting, panic recovery and eager snapshot semantics for these errors.
	return fmt.Errorf(prefix+"%w", err)
}

// ErrNotSupported is replaceable by callers. Only the original sentinel has a
// known, immutable message; replacements retain the original formatting path.
var originalErrNotSupported = ErrNotSupported

func unsupportedRunError(typ ProgramType) error {
	if ErrNotSupported == originalErrNotSupported {
		return &operationError{"kernel doesn't support running " + typ.String() + ": " + originalErrNotSupported.Error(), ErrNotSupported}
	}
	return fmt.Errorf("kernel doesn't support running %s: %w", typ, ErrNotSupported)
}
