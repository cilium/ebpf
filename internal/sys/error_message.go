package sys

import (
	"fmt"

	"github.com/cilium/ebpf/internal/unix"
)

// ErrnoMessage returns the message of an exact errno or wrappedErrno without
// invoking arbitrary error methods. In particular, syscallError is excluded:
// its message may come from an arbitrary error, including a fmt.Formatter.
func ErrnoMessage(err error) (string, bool) {
	switch e := err.(type) {
	case unix.Errno:
		return e.Error(), true
	case wrappedErrno:
		return e.Error(), true
	default:
		return "", false
	}
}

type signalError struct {
	message string
	cause   error
}

func (e *signalError) Error() string { return e.message }
func (e *signalError) Unwrap() error { return e.cause }

// profilerSignalError only constructs the panic payload. It must not change
// signal handling or OS thread locking and unlocking.
func profilerSignalError(prefix string, err error) error {
	if message, ok := ErrnoMessage(err); ok {
		return &signalError{prefix + message, err}
	}
	return fmt.Errorf(prefix+"%w", err)
}
