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

// FlushMapCache invalidates the entire cache storing feature probe results.
func FlushMapCache() {
	mc.mu.Lock()
	// could this approach introduce any unwanted side effects in multiple threads
	// even if we lock access to the cache structure?
	// should I rather delete() all the entries in the map?
	mc.mapTypes = make(map[ebpf.MapType]error)
	mc.mu.Unlock()
}

// FlushMapCacheEntry allows to delete a specified entry of the MapType feature cache.
func FlushMapCacheEntry(mt ebpf.MapType) {
	mc.mu.Lock()
	delete(mc.mapTypes, mt)
	mc.mu.Unlock()
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
	switch mt {
	case ebpf.StackTrace:
		// valueSize needs to be sizeof(uint64)
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
		// we can't support StructOps probes currently as it will require a valid BTF fd
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

// ProbeMapType allows probing the availability of a specified ebpf.MapType
// It will call the syscall to create a dummy map of a given ebpf.MapType at most once
// storing the result of the first call in a global cache.
// This potentially can result in false results if the calling process changes its permissions
// or capabilities.
// Calling programs can avoid false cached results by invalidating the cache through
// FlushMapCache() and FlushMapCacheEntry().
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
