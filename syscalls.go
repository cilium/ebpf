package ebpf

import (
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

const (
	bpfObjNameLen = 16
	bpfTagSize    = 8
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

type progLoadAttr struct {
	progType           ProgType
	insCount           uint32
	instructions       syscallPtr
	license            syscallPtr
	logLevel           uint32
	logSize            uint32
	logBuf             syscallPtr
	kernelVersion      uint32              // since 4.1  2541517c32be
	progFlags          uint32              // since 4.11 e07b98d9bffe
	progName           [bpfObjNameLen]byte // since 4.15 067cae47771c
	progIfIndex        uint32              // since 4.15 1f6f4cb7ba21
	expectedAttachType uint32              // since 4.17 5e43f899b03a
}

type progInfo struct {
	progType     uint32
	id           uint32
	tag          [bpfTagSize]byte
	jitedLen     uint32
	xlatedLen    uint32
	jited        syscallPtr
	xlated       syscallPtr
	loadTime     uint64 // since 4.15 cb4d2b3f03d8
	createdByUID uint32
	nrMapIDs     uint32
	mapIds       syscallPtr
	name         [bpfObjNameLen]byte
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

	wakeupEventsOrWatermark uint32
	bpType                  uint32
	bpAddr                  uint64
	bpLen                   uint64

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

func progLoad(attr *progLoadAttr) (uintptr, error) {
	return bpfCall(_ProgLoad, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
}

const bpfFSType = 0xcafe4a11

func pinObject(fileName string, fd uint32) error {
	dirName := filepath.Dir(fileName)
	var statfs syscall.Statfs_t
	if err := syscall.Statfs(dirName, &statfs); err != nil {
		return err
	}
	if statfs.Type != bpfFSType {
		return errors.Errorf("%s is not on a bpf filesystem", fileName)
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
	return uint32(ptr), errors.Wrapf(err, "object %s", fileName)
}

func getObjectInfoByFD(fd uint32, info unsafe.Pointer, size uintptr) error {
	// available from 4.13
	attr := objGetInfoByFDAttr{
		fd:      fd,
		infoLen: uint32(size),
		info:    newPtr(info),
	}
	_, err := bpfCall(_ObjGetInfoByFD, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return errors.Wrapf(err, "fd %d", fd)
}

func getMapSpecByFD(fd uint32) (*MapSpec, error) {
	var info mapInfo
	err := getObjectInfoByFD(fd, unsafe.Pointer(&info), unsafe.Sizeof(info))
	if err != nil {
		return nil, errors.Wrap(err, "can't get info for map")
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

func getProgInfoByFD(fd uint32) (*progInfo, error) {
	var info progInfo
	err := getObjectInfoByFD(fd, unsafe.Pointer(&info), unsafe.Sizeof(info))
	return &info, errors.Wrap(err, "can't get info for program")
}

func getMapFDByID(id uint32) (uint32, error) {
	// available from 4.13
	attr := getFDByIDAttr{
		id: id,
	}
	ptr, err := bpfCall(_MapGetFDByID, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return uint32(ptr), errors.Wrapf(err, "can't get fd for map id %d", id)
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
	if errNo != 0 {
		err = errNo
	}

	return r1, err
}

func perfEventOpen(attr *perfEventAttr, pid, cpu, groupFd int, flags uint) (int, error) {
	const flagCloexec = 1 << 3

	// Always overwrite size
	attr.size = uint32(unsafe.Sizeof(*attr))

	// Force CLOEXEC
	flags |= flagCloexec

	efd, _, errNo := syscall.Syscall6(_SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(attr)),
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

	return int(efd), err
}

func newEventFd() (int, error) {
	flags := syscall.O_CLOEXEC | syscall.O_NONBLOCK
	ret, _, errno := syscall.Syscall(syscall.SYS_EVENTFD2, uintptr(0), uintptr(flags), 0)
	if errno == 0 {
		return int(ret), nil
	}
	return -1, errors.Wrapf(errno, "can't create event fd")
}

func newEpollFd(fds ...int) (int, error) {
	epollfd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return -1, errors.Wrap(err, "can't create epoll fd")
	}

	for _, fd := range fds {
		event := unix.EpollEvent{
			Events: unix.EPOLLIN,
			Fd:     int32(fd),
		}

		err := unix.EpollCtl(epollfd, unix.EPOLL_CTL_ADD, fd, &event)
		if err != nil {
			syscall.Close(epollfd)
			return -1, errors.Wrap(err, "can't add fd to epoll")
		}
	}

	return epollfd, nil
}
