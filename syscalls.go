package ebpf

import (
	"fmt"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

type mapCreateAttr struct {
	mapType                               MapType
	keySize, valueSize, maxEntries, flags uint32
	innerMapFd                            uint32
}

type mapOpAttr struct {
	mapFd   uint32
	padding uint32
	key     syscallPtr
	value   syscallPtr
	flags   uint64
}

type mapInfo struct {
	mapType    uint32
	id         uint32
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	flags      uint32
}

type pinObjAttr struct {
	fileName syscallPtr
	fd       uint32
	padding  uint32
}

type progCreateAttr struct {
	progType      ProgType
	insCount      uint32
	instructions  syscallPtr
	license       syscallPtr
	logLevel      uint32
	logSize       uint32
	logBuf        syscallPtr
	kernelVersion uint32
	padding       uint32
}

const _BPF_TAG_SIZE = 8

type progInfo struct {
	progType  uint32
	id        uint32
	tag       [_BPF_TAG_SIZE]byte
	jitedLen  uint32
	xlatedLen uint32
	jited     syscallPtr
	xlated    syscallPtr
}

type perfEventAttr struct {
	perfType     uint32
	size         uint32
	config       uint64
	samplePeriod uint64
	sampleType   uint64
	readFormat   uint64

	// see include/uapi/linux/
	// for details
	flags uint64

	wakeupEvents uint32
	bpType       uint32
	bpAddr       uint64
	bpLen        uint64

	sampleRegsUser  uint64
	sampleStackUser uint32
	clockID         int32

	sampleRegsIntr uint64

	auxWatermark   uint32
	sampleMaxStack uint16

	padding uint16
}

type progTestRunAttr struct {
	fd          uint32
	retval      uint32
	dataSizeIn  uint32
	dataSizeOut uint32
	dataIn      syscallPtr
	dataOut     syscallPtr
	repeat      uint32
	duration    uint32
}

type objGetInfoByFDAttr struct {
	fd      uint32
	infoLen uint32
	info    syscallPtr // May be either mapInfo or progInfo
}

type getFDByIDAttr struct {
	id   uint32
	next uint32
}

func newPtr(ptr unsafe.Pointer) syscallPtr {
	return syscallPtr{ptr: ptr}
}

const bpfFSType = 0xcafe4a11

func pinObject(fileName string, fd uint32) error {
	dirName := filepath.Dir(fileName)
	var statfs syscall.Statfs_t
	if err := syscall.Statfs(dirName, &statfs); err != nil {
		return err
	}
	if statfs.Type != bpfFSType {
		return fmt.Errorf("%s is not on a bpf filesystem", fileName)
	}
	_, err := bpfCall(_ObjPin, unsafe.Pointer(&pinObjAttr{
		fileName: newPtr(unsafe.Pointer(&[]byte(fileName)[0])),
		fd:       fd,
	}), 16)
	return err
}

func getObject(fileName string) (uint32, error) {
	ptr, err := bpfCall(_ObjGet, unsafe.Pointer(&pinObjAttr{
		fileName: newPtr(unsafe.Pointer(&[]byte(fileName)[0])),
	}), 16)
	return uint32(ptr), err
}

func getObjectInfoByFD(fd uint32, info unsafe.Pointer, size uintptr) error {
	// available from 4.13
	attr := objGetInfoByFDAttr{
		fd:      fd,
		infoLen: uint32(size),
		info:    newPtr(info),
	}
	_, err := bpfCall(_ObjGetInfoByFD, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return err
}

func getMapSpecByFD(fd uint32) (*MapSpec, error) {
	var info mapInfo
	err := getObjectInfoByFD(uint32(fd), unsafe.Pointer(&info), unsafe.Sizeof(info))
	if err != nil {
		return nil, fmt.Errorf("ebpf: can't retrieve map info: %s", err.Error())
	}
	return &MapSpec{
		MapType(info.mapType),
		info.keySize,
		info.valueSize,
		info.maxEntries,
		info.flags,
		nil,
	}, nil
}

func getMapFDByID(id uint32) (uint32, error) {
	// available from 4.13
	attr := getFDByIDAttr{
		id: id,
	}
	ptr, err := bpfCall(_MapGetFDByID, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return uint32(ptr), err
}

type wrappedErrno struct {
	errNo   syscall.Errno
	message string
}

func (werr *wrappedErrno) Error() string {
	return werr.message
}

func (werr *wrappedErrno) Cause() error {
	return werr.errNo
}

func bpfCall(cmd int, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	r1, _, errNo := syscall.Syscall(uintptr(_BPFCall), uintptr(cmd), uintptr(attr), size)
	runtime.KeepAlive(attr)

	var err error
	switch errNo {
	case 0:
		err = nil
	case syscall.EPERM:
		err = &wrappedErrno{syscall.EPERM, "operation not permitted"}
	case syscall.EINVAL:
		err = &wrappedErrno{syscall.EINVAL, "invalid argument"}
	case syscall.ENOMEM:
		err = &wrappedErrno{syscall.ENOMEM, "out of memory"}
	case syscall.E2BIG:
		err = &wrappedErrno{syscall.E2BIG, "max entries exceeded"}
	case syscall.EFAULT:
		err = &wrappedErrno{syscall.EFAULT, "bad address"}
	case syscall.EBADF:
		err = &wrappedErrno{syscall.EBADF, "not an open file descriptor"}
	case syscall.EACCES:
		err = &wrappedErrno{syscall.EACCES, "bpf program rejected as unsafe"}
	default:
		err = errNo
	}

	return r1, err
}

func createPerfEvent(perfEvent *perfEventAttr, pid, cpu, groupFd int, flags uint) (uintptr, error) {
	efd, _, errNo := syscall.Syscall6(_SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(perfEvent)),
		uintptr(pid), uintptr(cpu), uintptr(groupFd), uintptr(flags), 0)

	var err error
	switch errNo {
	case 0:
		err = nil
	case syscall.E2BIG:
		err = &wrappedErrno{syscall.E2BIG, "perf_event_attr size is incorrect, check size field for what the correct size should be"}
	case syscall.EACCES:
		err = &wrappedErrno{syscall.EACCES, "insufficient capabilities to create this event"}
	case _EBADFD:
		err = &wrappedErrno{_EBADFD, "group_fd is invalid"}
	case syscall.EBUSY:
		err = &wrappedErrno{syscall.EBUSY, "another event already has exclusive access to the PMU"}
	case syscall.EFAULT:
		err = &wrappedErrno{syscall.EFAULT, "attr points to an invalid address"}
	case syscall.EINVAL:
		err = &wrappedErrno{syscall.EINVAL, "the specified event is invalid, most likely because a configuration parameter is invalid (i.e. too high, too low, etc)"}
	case syscall.EMFILE:
		err = &wrappedErrno{syscall.EMFILE, "this process has reached its limits for number of open events that it may have"}
	case syscall.ENODEV:
		err = &wrappedErrno{syscall.ENODEV, "this processor architecture does not support this event type"}
	case syscall.ENOENT:
		err = &wrappedErrno{syscall.ENOENT, "the type setting is not valid"}
	case syscall.ENOSPC:
		err = &wrappedErrno{syscall.ENOSPC, "the hardware limit for breakpoints capacity has been reached"}
	case syscall.ENOSYS:
		err = &wrappedErrno{syscall.ENOSYS, "sample type not supported by the hardware"}
	case syscall.EOPNOTSUPP:
		err = &wrappedErrno{syscall.EOPNOTSUPP, "this event is not supported by the hardware or requires a feature not supported by the hardware"}
	case syscall.EOVERFLOW:
		err = &wrappedErrno{syscall.EOVERFLOW, "sample_max_stack is larger than the kernel support; check \"/proc/sys/kernel/perf_event_max_stack\" for maximum supported size"}
	case syscall.EPERM:
		err = &wrappedErrno{syscall.EPERM, "insufficient capability to request exclusive access"}
	case syscall.ESRCH:
		err = &wrappedErrno{syscall.ESRCH, "pid does not exist"}
	default:
		err = errNo
	}

	return efd, err
}

// IOCtl The ioctl() function manipulates the underlying device parameters of
// special files.  In particular, many operating characteristics of
// character special files (e.g., terminals) may be controlled with
// ioctl() requests.  The argument fd must be an open file descriptor.
// The second argument is a device-dependent request code.  The third
// argument is an untyped pointer to memory.  It's traditionally char
// *argp (from the days before void * was valid C).
// An ioctl() request has encoded in it whether the argument is an in
// parameter or out parameter, and the size of the argument argp in
// bytes.
func IOCtl(fd int, args ...uint64) error {
	if len(args) > 2 {
		return fmt.Errorf("too many arguments to IOCtl, 3 is the maximum")
	}
	var tmp [2]uintptr
	for i, a := range args {
		tmp[i] = uintptr(a)
	}
	_, _, errNo := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), tmp[0], tmp[1])

	switch errNo {
	case 0:
		return nil
	case syscall.EFAULT:
		return fmt.Errorf("argp references an inaccessible memory area")
	case syscall.EINVAL:
		return fmt.Errorf("request or argp is not valid")
	case syscall.ENOTTY:
		return fmt.Errorf("the specified request does not apply to the kind of object that the file descriptor references")
	}
	return errNo
}
