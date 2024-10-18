//go:build windows

// Package efw contains support code for eBPF for Windows.
package efw

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

// Module is the global handle for the eBPF for Windows user-space API.
var Module = windows.NewLazyDLL("ebpfapi.dll")

// FD is the equivalent of fd_t.
//
// See https://github.com/microsoft/ebpf-for-windows/blob/54632eb360c560ebef2f173be1a4a4625d540744/include/ebpf_api.h#L24
type FD int32

// Size is the equivalent of size_t.
//
// TODO(windows): This is correct on amd64 and arm64, AFACIT. Are there weird corner
// cases like LP32?
type Size uint64

// Call a function which returns a C int.
//
//go:uintptrescapes
func CallInt(proc *windows.LazyProc, args ...uintptr) (int, windows.Errno, error) {
	if err := proc.Find(); err != nil {
		return 0, 0, fmt.Errorf("%s: %w", proc.Name, err)
	}

	res, _, err := proc.Call(args...)
	return int(int32(res)), err.(windows.Errno), nil
}

// Call a function which returns ebpf_result_t.
//
//go:uintptrescapes
func CallResult(proc *windows.LazyProc, args ...uintptr) error {
	if err := proc.Find(); err != nil {
		return fmt.Errorf("%s: %w", proc.Name, err)
	}

	res, _, errNo := proc.Call(args...)
	if err := ResultToError(Result(res)); err != nil {
		if errNo.(syscall.Errno) != 0 {
			return fmt.Errorf("%s: %w (errno: %v)", proc.Name, err, errNo)
		}
		return fmt.Errorf("%s: %w", proc.Name, err)
	}
	return nil
}

// Call a function which returns fd_t.
//
//go:uintptrescapes
func CallFd(proc *windows.LazyProc, args ...uintptr) (FD, error) {
	if err := proc.Find(); err != nil {
		return -1, fmt.Errorf("%s: %w", proc.Name, err)
	}

	res, _, _ := proc.Call(args...)
	return FD(res), nil
}
