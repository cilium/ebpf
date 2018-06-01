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

func bpfErrNo(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case syscall.EPERM:
		return fmt.Errorf("operation not permitted")
	case syscall.EINVAL:
		return fmt.Errorf("invalid argument")
	case syscall.ENOMEM:
		return fmt.Errorf("out of memory")
	case syscall.E2BIG:
		return fmt.Errorf("max entries exceeded")
	case syscall.EFAULT:
		return fmt.Errorf("bad address")
	case syscall.EBADF:
		return fmt.Errorf("not an open file descriptor")
	case syscall.EACCES:
		return fmt.Errorf("bpf program rejected as unsafe")
	case syscall.ENOSPC:
		return fmt.Errorf("bpf logging buffer not large enough")
	}
	return e
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
	_, errNo := bpfCall(_ObjPin, unsafe.Pointer(&pinObjAttr{
		fileName: newPtr(unsafe.Pointer(&[]byte(fileName)[0])),
		fd:       fd,
	}), 16)
	return bpfErrNo(errNo)
}

func getObject(fileName string) (uint32, error) {
	ptr, errNo := bpfCall(_ObjGet, unsafe.Pointer(&pinObjAttr{
		fileName: newPtr(unsafe.Pointer(&[]byte(fileName)[0])),
	}), 16)
	return uint32(ptr), bpfErrNo(errNo)
}

func getObjectInfoByFD(fd uint32, info unsafe.Pointer, size uintptr) error {
	// available from 4.13
	attr := objGetInfoByFDAttr{
		fd:      fd,
		infoLen: uint32(size),
		info:    newPtr(info),
	}
	_, errNo := bpfCall(_ObjGetInfoByFD, unsafe.Pointer(&attr), int(unsafe.Sizeof(attr)))
	return bpfErrNo(errNo)
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
	ptr, errNo := bpfCall(_MapGetFDByID, unsafe.Pointer(&attr), int(unsafe.Sizeof(attr)))
	return uint32(ptr), bpfErrNo(errNo)
}

func bpfCall(cmd int, attr unsafe.Pointer, size int) (uintptr, syscall.Errno) {
	r1, _, errNo := syscall.Syscall(uintptr(_BPFCall), uintptr(cmd), uintptr(attr), uintptr(size))
	runtime.KeepAlive(attr)
	return r1, errNo
}

func createPerfEvent(perfEvent *perfEventAttr, pid, cpu, groupFd int, flags uint) (uintptr, error) {
	efd, _, errNo := syscall.Syscall6(_SYS_PERF_EVENT_OPEN, uintptr(unsafe.Pointer(perfEvent)),
		uintptr(pid), uintptr(cpu), uintptr(groupFd), uintptr(flags), 0)

	switch errNo {
	case 0:
		return efd, nil
	case syscall.E2BIG:
		return 0, fmt.Errorf("perf_event_attr size is incorrect, check size field for what the correct size should be")
	case syscall.EACCES:
		return 0, fmt.Errorf("insufficient capabilities to create this event")
	case _EBADFD:
		return 0, fmt.Errorf("group_fd is invalid")
	case syscall.EBUSY:
		return 0, fmt.Errorf("another event already has exclusive access to the PMU")
	case syscall.EFAULT:
		return 0, fmt.Errorf("attr points to an invalid address")
	case syscall.EINVAL:
		return 0, fmt.Errorf("the specified event is invalid, most likely because a configuration parameter is invalid (i.e. too high, too low, etc)")
	case syscall.EMFILE:
		return 0, fmt.Errorf("this process has reached its limits for number of open events that it may have")
	case syscall.ENODEV:
		return 0, fmt.Errorf("this processor architecture does not support this event type")
	case syscall.ENOENT:
		return 0, fmt.Errorf("the type setting is not valid")
	case syscall.ENOSPC:
		return 0, fmt.Errorf("the hardware limit for breakpoints capacity has been reached")
	case syscall.ENOSYS:
		return 0, fmt.Errorf("sample type not supported by the hardware")
	case syscall.EOPNOTSUPP:
		return 0, fmt.Errorf("this event is not supported by the hardware or requires a feature not supported by the hardware")
	case syscall.EOVERFLOW:
		return 0, fmt.Errorf("sample_max_stack is larger than the kernel support; check \"/proc/sys/kernel/perf_event_max_stack\" for maximum supported size")
	case syscall.EPERM:
		return 0, fmt.Errorf("insufficient capability to request exclusive access")
	case syscall.ESRCH:
		return 0, fmt.Errorf("pid does not exist")
	}
	return 0, errNo
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
