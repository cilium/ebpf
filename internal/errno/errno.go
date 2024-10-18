package errno

import "runtime"

var (
	errEAGAIN error = wrappedErrno{EAGAIN}
	errEINVAL error = wrappedErrno{EINVAL}
	errENOENT error = wrappedErrno{ENOENT}
)

// Error converts an errno into an error.
//
// It is faster than directly converting to an error for some common errnos.
func Error(e Errno) error {
	switch e {
	case 0:
		return nil
	case EAGAIN:
		return errEAGAIN
	case EINVAL:
		return errEINVAL
	case ENOENT:
		return errENOENT
	}
	return wrappedErrno{e}
}

// wrappedErrno wraps Errno to prevent direct comparisons with
// syscall.E* or unix.E* constants.
//
// You should never export an error of this type.
type wrappedErrno struct {
	Errno
}

func (we wrappedErrno) Unwrap() error {
	return we.Errno
}

func (we wrappedErrno) Error() string {
	if runtime.GOOS == "linux" && we.Errno == ENOTSUPP {
		return "operation not supported"
	}
	return we.Errno.Error()
}
