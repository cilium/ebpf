package link

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"golang.org/x/sys/unix"
)

type TracepointOptions struct {
	// Tracepoint name.
	Name string
	// Program must be of type TracePoint
	Program *ebpf.Program
}

// tracepoint is a perf event based tracepoint.
type tracepoint struct {
	fd *internal.FD
}

// AttachTracepoint attaches a program to a perf event based tracepoint.
func AttachTracepoint(opts TracepointOptions) (Link, error) {
	tid, err := getTracepointID(opts.Name)
	if err != nil {
		return nil, err
	}

	attr := unix.PerfEventAttr{
		Type:        unix.PERF_TYPE_TRACEPOINT,
		Config:      tid,
		Sample_type: unix.PERF_SAMPLE_RAW,
		Sample:      1,
		Wakeup:      1,
	}
	pfd, err := unix.PerfEventOpen(&attr, -1, 0, -1, unix.PERF_FLAG_FD_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("open perf event: %s", err)
	}

	if err := unix.IoctlSetInt(pfd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		unix.Close(pfd)
		return nil, fmt.Errorf("enable perf event: %s", err)
	}

	tp := &tracepoint{internal.NewFD(uint32(pfd))}
	if err := tp.Update(opts.Program); err != nil {
		tp.Close()
		return nil, err
	}

	return tp, nil
}

func (tp *tracepoint) isLink() {}

func (tp *tracepoint) Pin(string) error {
	return fmt.Errorf("pin tracepoint: %w", ErrNotSupported)
}

func (tp *tracepoint) Update(prog *ebpf.Program) error {
	if t := prog.Type(); t != ebpf.TracePoint {
		return fmt.Errorf("invalid program type %s", t)
	}
	if prog.FD() < 0 {
		return fmt.Errorf("invalid program: %w", internal.ErrClosedFd)
	}

	pfd, err := tp.fd.Value()
	if err != nil {
		return fmt.Errorf("tracepoint fd: %s", err)
	}

	err = unix.IoctlSetInt(int(pfd), unix.PERF_EVENT_IOC_SET_BPF, prog.FD())
	if err != nil {
		return fmt.Errorf("update tracepoint: %s", err)
	}
	return nil
}

// Close disables the tracepoint.
func (tp *tracepoint) Close() error {
	return tp.fd.Close()
}

func getTracepointID(name string) (uint64, error) {
	// Prevent directory traversal attacks
	path := filepath.Join("/", name)
	path = filepath.Join("/sys/kernel/debug/tracing/events", path, "id")
	data, err := ioutil.ReadFile(path)
	if os.IsNotExist(err) {
		return 0, fmt.Errorf("tracepoint %q: %w", name, ErrNotSupported)
	}
	if err != nil {
		return 0, fmt.Errorf("read tracepoint ID of %q: %s", name, err)
	}
	tid := strings.TrimSuffix(string(data), "\n")
	return strconv.ParseUint(tid, 10, 64)
}
