package features

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

type MapCache struct {
	mu       sync.RWMutex
	mapTypes map[ebpf.MapType]error
}

var (
	mc MapCache
)

func init() {
	mc.mapTypes = make(map[ebpf.MapType]error)
}

func probeMapTypeAttr(mt ebpf.MapType) *internal.BPFMapCreateAttr {
	var (
		keySize               uint32 = 4
		valueSize             uint32 = 4
		maxEntries            uint32 = 1
		innerMapFd            uint32
		flags                 uint32
		btfKeyTypeID          uint32
		btfValueTypeID        uint32
		btfFd                 uint32
		btfVmLinuxValueTypeID uint32
	)

	// switch on map types to generate correct bpfMapCreateAttr
	// BPF_MAP_TYPE_STRUCT_OPS, BPF_MAP_TYPE_RINGBUF, BPF_MAP_TYPE_INODE_STORAGE, BPF_MAP_TYPE_TASK_STORAGE
	// are added with open ringbuf PR
	switch mt {
	case ebpf.StackTrace:
		valueSize = 8
	case ebpf.LPMTrie:
		keySize = 8
		valueSize = 8
		flags = unix.BPF_F_NO_PREALLOC
	case ebpf.ArrayOfMaps:
		fallthrough
	case ebpf.HashOfMaps:
		innerMapFd = ^uint32(0)
	case ebpf.CGroupStorage:
		fallthrough
	case ebpf.PerCPUCGroupStorage:
		// Why struct{u32 + u64} = 12 + padding = 16 ? can it be 12 for 32-bit cpus?
		keySize = 16
		valueSize = 8
		maxEntries = 0
	case ebpf.Queue:
		fallthrough
	case ebpf.Stack:
		keySize = 0
	case ebpf.StructOpts:
		// does not work currently
		btfVmLinuxValueTypeID = 1
	case ebpf.RingBuf:
		keySize = 0
		valueSize = 0
		maxEntries = 4096
	case ebpf.SkStorage:
		fallthrough
	case ebpf.InodeStorage:
		fallthrough
	case ebpf.TaskStorage:
		valueSize = 8
		maxEntries = 0
		flags = unix.BPF_F_NO_PREALLOC
		btfKeyTypeID = 1
		btfValueTypeID = 3
		btfFd = ^uint32(0)
	}

	return &internal.BPFMapCreateAttr{
		MapType:               uint32(mt),
		KeySize:               keySize,
		ValueSize:             valueSize,
		MaxEntries:            maxEntries,
		InnerMapFd:            innerMapFd,
		Flags:                 flags,
		BTFKeyTypeID:          btfKeyTypeID,
		BTFValueTypeID:        btfValueTypeID,
		BTFFd:                 btfFd,
		BTFVmLinuxValueTypeID: btfVmLinuxValueTypeID,
	}

}

func ProbeMapType(mt ebpf.MapType) error {
	// make sure to bound Map types
	// MaxMapType new value in enum, easier to handle than making sure
	// we are checking the last value in the enum (which could eventually change)
	if mt >= ebpf.MaxMapType {
		return internal.ErrNotSupported
	}

	mc.mu.RLock()
	if err, ok := mc.mapTypes[mt]; ok {
		defer mc.mu.RUnlock()
		return err
	}
	mc.mu.RUnlock()

	attr := probeMapTypeAttr(mt)
	_, err := internal.BPFMapCreate(attr)

	// For nested and storage maps we accept EBADF as indicator that nested maps are supported
	if errors.Is(err, unix.EBADF) {
		if isNestedMap(mt) || isStorageMap(mt) {
			err = nil
		}
	}

	// interpret kernel error as own error interface
	// obviously needs more than just the err != nil check
	if err != nil {
		fmt.Println(err)
		err = internal.ErrNotSupported
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.mapTypes[mt] = err

	return err
}

func isNestedMap(mt ebpf.MapType) bool {
	if mt == ebpf.ArrayOfMaps || mt == ebpf.HashOfMaps {
		return true
	}
	return false
}

func isStorageMap(mt ebpf.MapType) bool {
	if mt == ebpf.SkStorage || mt == ebpf.InodeStorage || mt == ebpf.TaskStorage {
		return true
	}
	return false
}
