//go:build windows

// Package efw contains support code for eBPF for Windows.
package efw

import (
	"golang.org/x/sys/windows"
)

// module is the global handle for the eBPF for Windows user-space API.
var module = windows.NewLazyDLL("ebpfapi.dll")

// FD is the equivalent of fd_t.
//
// See https://github.com/microsoft/ebpf-for-windows/blob/54632eb360c560ebef2f173be1a4a4625d540744/include/ebpf_api.h#L24
type FD int32

// size is the equivalent of size_t.
//
// TODO(windows): This is correct on amd64 and arm64, AFACIT. Are there weird corner
// cases like LP32?
type size uint64
