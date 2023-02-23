package internal

import (
	"unsafe"

	"github.com/cilium/ebpf/internal/unix"
)

const (
	BpfFSType   = 0xcafe4a11
	TraceFSType = 0x74726163
	DebugFSType = 0x64626720
)

func FSType(path string) (int64, error) {
	var statfs unix.Statfs_t
	if err := unix.Statfs(path, &statfs); err != nil {
		return 0, err
	}

	fsType := int64(statfs.Type)
	if unsafe.Sizeof(statfs.Type) == 4 {
		// We're on a 32 bit arch, where statfs.Type is int32. bpfFSType is a
		// negative number when interpreted as int32 so we need to cast via
		// uint32 to avoid sign extension.
		fsType = int64(uint32(statfs.Type))
	}
	return fsType, nil
}
