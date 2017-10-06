package ebpf

import (
	"fmt"
	"syscall"
	"unsafe"
)

type mapCreateAttr struct {
	mapType                               MapType
	keySize, valueSize, maxEntries, flags uint32
}

type mapOpAttr struct {
	mapFd   uint32
	padding uint32
	key     uint64
	value   uint64
	flags   uint64
}

type pinObjAttr struct {
	fileName uint64
	fd       uint32
	padding  uint32
}

type progCreateAttr struct {
	progType      ProgType
	insCount      uint32
	instructions  uint64
	license       uint64
	logLevel      uint32
	logSize       uint32
	logBuf        uint64
	kernelVersion uint32
	padding       uint32
}

// size 104
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

func pinObject(fileName string, fd uint32) error {
	_, errNo := bpfCall(_BPF_OBJ_PIN, unsafe.Pointer(&pinObjAttr{
		fileName: uint64(uintptr(unsafe.Pointer(&[]byte(fileName)[0]))),
		fd:       fd,
	}), 16)
	return bpfErrNo(errNo)
}

func getObject(fileName string) (uintptr, error) {
	ptr, errNo := bpfCall(_BPF_OBJ_GET, unsafe.Pointer(&pinObjAttr{
		fileName: uint64(uintptr(unsafe.Pointer(&[]byte(fileName)[0]))),
	}), 16)
	return ptr, bpfErrNo(errNo)
}

func bpfCall(cmd int, attr unsafe.Pointer, size int) (uintptr, syscall.Errno) {
	r1, _, errNo := syscall.Syscall(uintptr(_BPFCall), uintptr(cmd), uintptr(attr), uintptr(size))
	return r1, errNo
}

func createPerfEvent(perfEvent *perfEventAttr, pid, cpu, groupFd int, flags uint) (uintptr, error) {

	ptr := unsafe.Pointer(perfEvent)
	efd, _, errNo := syscall.Syscall6(_PerfEvent, uintptr(ptr),
		uintptr(pid), uintptr(cpu), uintptr(groupFd), uintptr(flags), 0)
	err := eventErrNo(errNo)
	if err != nil {
		return 0, err
	}
	return efd, nil
}

func eventErrNo(errNo syscall.Errno) error {
	switch errNo {
	case 0:
		return nil
	case syscall.E2BIG:
		return fmt.Errorf("perf_event_attr size is incorrect, check size field for what the correct size should be")
	case syscall.EACCES:
		return fmt.Errorf("insufficient capabilities to create this event")
	case syscall.EBADFD:
		return fmt.Errorf("group_fd is invalid")
	case syscall.EBUSY:
		return fmt.Errorf("another event already has exclusive access to the PMU")
	case syscall.EFAULT:
		return fmt.Errorf("attr points to an invalid address")
	case syscall.EINVAL:
		return fmt.Errorf("the specified event is invalid, most likely because a configuration parameter is invalid (i.e. too high, too low, etc)")
	case syscall.EMFILE:
		return fmt.Errorf("this process has reached its limits for number of open events that it may have")
	case syscall.ENODEV:
		return fmt.Errorf("this processor architecture does not support this event type")
	case syscall.ENOENT:
		return fmt.Errorf("the type setting is not valid")
	case syscall.ENOSPC:
		return fmt.Errorf("the hardware limit for breakpoints capacity has been reached")
	case syscall.ENOSYS:
		return fmt.Errorf("sample type not supported by the hardware")
	case syscall.EOPNOTSUPP:
		return fmt.Errorf("this event is not supported by the hardware or requires a feature not supported by the hardware")
	case syscall.EOVERFLOW:
		return fmt.Errorf("sample_max_stack is larger than the kernel support; check \"/proc/sys/kernel/perf_event_max_stack\" for maximum supported size")
	case syscall.EPERM:
		return fmt.Errorf("insufficient capability to request exclusive access")
	case syscall.ESRCH:
		return fmt.Errorf("pid does not exist")
	}
	return errNo
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
	return ioctlErrNo(errNo)
}

func ioctlErrNo(errNo syscall.Errno) error {
	switch errNo {
	case 0:
		return nil
	case syscall.EBADFD:
		return fmt.Errorf("not a valid file descriptor")
	case syscall.EFAULT:
		return fmt.Errorf("argp references an inaccessible memory area")
	case syscall.EINVAL:
		return fmt.Errorf("request or argp is not valid")
	case syscall.ENOTTY:
		return fmt.Errorf("the specified request does not apply to the kind of object that the file descriptor references")

	}
	return errNo
}
