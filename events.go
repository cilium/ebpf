package ebpf

import (
	"fmt"
	"os"
	"path"
	"strconv"
)

const (
	_DebugFS      = "/sys/kernel/debug/tracing/"
	_KprobeEvents = _DebugFS + "kprobe_events"
	_EventsDir    = _DebugFS + "events"
)

// PerfEventCmd is an ioctl control flag that signals to the kernel
// various commands to created perf events. A careful look at
// how the flags are constructed will help in understanding
// what arguments are "owed" to the ioctl syscall.
type PerfEventCmd uint64

const (
	_IOCNone  = 0
	_IOCWrite = 1
	_IOCRead  = 2

	_IOCNRBits   = 8
	_IOCTypeBits = 8
	_IOCSizeBits = 14

	_IOCNRShift   = 0
	_IOCTypeShift = _IOCNRShift + _IOCNRBits
	_IOCSizeShift = _IOCTypeShift + _IOCTypeBits
	_IOCDirShift  = _IOCSizeShift + _IOCSizeBits

	_IOCWriteConst = _IOCWrite << _IOCDirShift
	_IOCReadConst  = _IOCRead << _IOCDirShift
	_TypeConst     = '$' << _IOCTypeShift
	_Size64Const   = 8 << _IOCSizeShift
	_Size32Const   = 4 << _IOCSizeShift

	// IOCEnable - This enables the individual event or event group specified by
	// the file descriptor argument.
	IOCEnable = PerfEventCmd(_TypeConst)
	// IOCDisable - This disables the individual counter or event group specified
	// by the file descriptor argument.
	IOCDisable = PerfEventCmd(_TypeConst | 1<<_IOCNRShift)
	// IOCRefresh - Non-inherited overflow counters can use this to enable a
	// counter for a number of overflows specified by the argument,
	// after which it is disabled.  Subsequent calls of this ioctl
	// add the argument value to the current count.  An overflow
	// notification with POLL_IN set will happen on each overflow
	// until the count reaches 0; when that happens a notification
	// with POLL_HUP set is sent and the event is disabled.  Using an
	// argument of 0 is considered undefined behavior.
	IOCRefresh = PerfEventCmd(_TypeConst | 2<<_IOCNRShift)
	// IOCReset - Reset the event count specified by the file descriptor argu‐
	// ment to zero.  This resets only the counts; there is no way to
	// reset the multiplexing time_enabled or time_running values.
	IOCReset = PerfEventCmd(_TypeConst | 3<<_IOCNRShift)
	// IOCPeriod - This updates the overflow period for the event.
	// Since Linux 3.7 (on ARM) and Linux 3.14 (all other architec‐
	// tures), the new period takes effect immediately.  On older
	// kernels, the new period did not take effect until after the
	// next overflow.
	// The argument is a pointer to a 64-bit value containing the
	// desired new period.
	// Prior to Linux 2.6.36, this ioctl always failed due to a bug
	// in the kernel.
	IOCPeriod = PerfEventCmd(_IOCWriteConst | _TypeConst | _Size64Const | 4<<_IOCNRShift)
	// IOCSetOutput - This tells the kernel to report event notifications to the
	// specified file descriptor rather than the default one.  The
	// file descriptors must all be on the same CPU.
	// The argument specifies the desired file descriptor, or -1 if
	// output should be ignored.
	IOCSetOutput = PerfEventCmd(_TypeConst | 5<<_IOCNRShift)
	// IOCSetFilter -  This adds an ftrace filter to this event.
	// The argument is a pointer to the desired ftrace filter.
	IOCSetFilter = PerfEventCmd(_IOCWriteConst | _TypeConst | _Size64Const | 6<<_IOCNRShift)
	// IOCID - This returns the event ID value for the given event file
	// descriptor.
	// The argument is a pointer to a 64-bit unsigned integer to hold
	// the result.
	IOCID = PerfEventCmd(_IOCReadConst | _TypeConst | _Size64Const | 7<<_IOCNRShift)
	// IOCSetBPF - This allows attaching a Berkeley Packet Filter (BPF) program
	// to an existing kprobe tracepoint event.  You need
	// CAP_SYS_ADMIN privileges to use this ioctl.
	// The argument is a BPF program file descriptor that was created
	// by a previous bpf(2) system call.
	IOCSetBPF = PerfEventCmd(_IOCWriteConst | _TypeConst | _Size32Const | 8<<_IOCNRShift)
	// IOCPauseOutput - This allows pausing and resuming the event's ring-buffer. A
	// paused ring-buffer does not prevent samples generation, but simply
	// discards them. The discarded samples are considered lost.
	// The argument is an integer. Nonzero value pauses the ring-buffer,
	// zero value resumes the ring-buffer.
	IOCPauseOutput = PerfEventCmd(_IOCWriteConst | _TypeConst | _Size32Const | 9<<_IOCNRShift)
)

// CreateKprobe creates a kprobe in the linux kernel
func CreateKprobe(event string, fd Program) error {
	return createKprobe('p', "kprobe", event, fd)
}

// CreateKretprobe creates a kretprobe in the linux kernel
func CreateKretprobe(event string, fd Program) error {
	return createKprobe('r', "kretprobe", event, fd)
}

func createKprobe(typ rune, base, event string, fd Program) error {
	f, err := os.OpenFile(_KprobeEvents, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("%c:%s %s", typ, base, event))
	if err != nil {
		return err
	}
	return CreateTracepoint(event, fd)
}

// CreateTracepoint creates a tracepoint in the linux kernel
func CreateTracepoint(event string, fd Program) error {
	attr := new(perfEventAttr)
	attr.perfType = 2
	attr.sampleType = 1 << 10
	attr.samplePeriod = 1
	attr.wakeupEvents = 1
	f, err := os.Open(path.Join(_DebugFS, _EventsDir, event))
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 256)
	_, err = f.Read(buf)
	if err != nil {
		return err
	}
	id, err := strconv.Atoi(string(buf))
	if err != nil {
		return err
	}
	attr.config = uint64(id)
	eFd, err := createPerfEvent(attr, -1, 0, -1, 0)
	err = IOCtl(int(eFd), uint64(IOCEnable))
	if err != nil {
		return err
	}
	err = IOCtl(int(eFd), uint64(IOCSetBPF), uint64(fd.GetFd()))
	return err
}
