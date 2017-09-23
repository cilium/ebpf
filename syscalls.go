// Copyright 2017 Nathan Sweet. All rights reserved.
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
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

func errnoErr(e syscall.Errno) error {
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
	return errnoErr(errNo)
}

func getObject(fileName string) (uintptr, error) {
	ptr, errNo := bpfCall(_BPF_OBJ_GET, unsafe.Pointer(&pinObjAttr{
		fileName: uint64(uintptr(unsafe.Pointer(&[]byte(fileName)[0]))),
	}), 16)
	return ptr, errnoErr(errNo)
}

func bpfCall(cmd int, attr unsafe.Pointer, size int) (uintptr, syscall.Errno) {
	r1, _, errNo := syscall.Syscall(uintptr(_BPF_CALL), uintptr(cmd), uintptr(attr), uintptr(size))
	return r1, errNo
}
