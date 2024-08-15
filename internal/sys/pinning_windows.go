package sys

import (
	"errors"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf/internal/efw"
)

// ebpf_result_t ebpf_object_unpin(_In_z_ const char* path)
var procEbpfObjectUnpin = efw.Module.NewProc("ebpf_object_unpin")

func Pin(currentPath, newPath string, fd *FD) error {
	defer runtime.KeepAlive(fd)

	if newPath == "" {
		return errors.New("given pinning path cannot be empty")
	}
	if currentPath == newPath {
		return nil
	}

	if currentPath == "" {
		return ObjPin(&ObjPinAttr{
			Pathname: NewStringPointer(newPath),
			BpfFd:    fd.Uint(),
		})
	}

	// TODO(windows): This should not allow replacing an existing object.
	return ObjPin(&ObjPinAttr{
		Pathname: NewStringPointer(newPath),
		BpfFd:    fd.Uint(),
	})
}

func Unpin(pinnedPath string) error {
	if pinnedPath == "" {
		return nil
	}

	pinnedPathBytes, err := ByteSliceFromString(pinnedPath)
	if err != nil {
		return err
	}

	return efw.CallResult(procEbpfObjectUnpin, uintptr(unsafe.Pointer(&pinnedPathBytes[0])))
}
