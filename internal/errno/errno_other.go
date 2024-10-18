//go:build !linux && !windows

package errno

import "syscall"

type Errno = syscall.Errno

// Errnos are distinct and non-zero.
const (
	ENOENT syscall.Errno = iota + 1
	EEXIST
	EAGAIN
	ENOSPC
	EINVAL
	EINTR
	EPERM
	ESRCH
	ENODEV
	EBADF
	E2BIG
	EFAULT
	EACCES
	EILSEQ
	EOPNOTSUPP
	ESTALE
	ENOTSUPP
)
