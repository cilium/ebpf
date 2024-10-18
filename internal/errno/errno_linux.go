package errno

import (
	"syscall"
)

type Errno = syscall.Errno

const (
	EPERM      Errno = syscall.EPERM
	ENOENT     Errno = syscall.ENOENT
	ESRCH      Errno = syscall.ESRCH
	EINTR      Errno = syscall.EINTR
	E2BIG      Errno = syscall.E2BIG
	EBADF      Errno = syscall.EBADF
	EAGAIN     Errno = syscall.EAGAIN
	EACCES     Errno = syscall.EACCES
	EFAULT     Errno = syscall.EFAULT
	EEXIST     Errno = syscall.EEXIST
	ENODEV     Errno = syscall.ENODEV
	EINVAL     Errno = syscall.EINVAL
	ENOSPC     Errno = syscall.ENOSPC
	EILSEQ     Errno = syscall.EILSEQ
	EOPNOTSUPP Errno = syscall.EOPNOTSUPP
	ESTALE     Errno = syscall.ESTALE

	// ENOTSUPP is a Linux internal error code that has leaked into UAPI.
	//
	// It is not the same as ENOTSUP or EOPNOTSUPP.
	ENOTSUPP Errno = 524
)
