package features

import (
	"errors"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

var ErrInconclusive = errors.New("probe was inconclusive")

type MapCache struct {
	sync.RWMutex
	mapTypes map[ebpf.MapType]error
}

var (
	mapCache MapCache
)

func init() {
	mapCache.mapTypes = make(map[ebpf.MapType]error)
}

// FlushMapCache invalidates the entire cache storing feature probe results.
func FlushMapCache() {
	mapCache.Lock()
	mapCache.mapTypes = make(map[ebpf.MapType]error)
	mapCache.Unlock()
}

// FlushMapCacheEntry allows to delete a specified entry of the MapType feature cache.
func FlushMapCacheEntry(mt ebpf.MapType) {
	mapCache.Lock()
	delete(mapCache.mapTypes, mt)
	mapCache.Unlock()
}

func createMapTypeAttr(mt ebpf.MapType) *internal.BPFMapCreateAttr {
	var (
		keySize               uint32 = 4
		valueSize             uint32 = 4
		maxEntries            uint32 = 1
		innerMapFd            uint32
		flags                 uint32
		btfKeyTypeID          uint32
		btfValueTypeID        uint32
		btfFd                 uint32
		btfVmlinuxValueTypeID uint32
	)

	// switch on map types to generate correct bpfMapCreateAttr
	switch mt {
	case ebpf.StackTrace:
		// valueSize needs to be sizeof(uint64)
		valueSize = 8
	case ebpf.LPMTrie:
		// keySize and valueSize need to be sizeof(struct{u32 + u8}) + 1 + padding = 8
		// BPF_F_NO_PREALLOC needs to be set
		// checked at allocation time for lpm_trie maps
		keySize = 8
		valueSize = 8
		flags = unix.BPF_F_NO_PREALLOC
	case ebpf.ArrayOfMaps, ebpf.HashOfMaps:
		// assign invalid innerMapFd to pass validation check
		// will return EBADF
		innerMapFd = ^uint32(0)
	case ebpf.CGroupStorage, ebpf.PerCPUCGroupStorage:
		// keySize and valueSize need to be sizeof(struct{u32 + u64}) = 12 + padding = 16
		// can it be 12 for 32-bit cpus?
		// checked at allocation time
		keySize = 16
		maxEntries = 0
	case ebpf.Queue, ebpf.Stack:
		// keySize needs to be 0, see alloc_check for queue and stack maps
		keySize = 0
	case ebpf.RingBuf:
		// keySize and valueSize need to be 0
		// maxEntries needs to be power of 2 and PAGE_ALIGNED
		// checked at allocation time
		keySize = 0
		valueSize = 0
		maxEntries = 4096
	case ebpf.SkStorage, ebpf.InodeStorage, ebpf.TaskStorage:
		// maxEntries needs to be 0
		// BPF_F_NO_PREALLOC needs to be set
		// btf* fields need to be set
		// see alloc_check for local_storage map types
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
		BTFVmlinuxValueTypeID: btfVmlinuxValueTypeID,
	}

}

// HaveMapType allows probing the availability of a specified ebpf.MapType
// It will call the syscall to create a dummy map of a given ebpf.MapType at most once
// storing the result of the first call in a global cache.
// This potentially can result in false results if the calling process changes its capabilities.
// Calling programs can avoid false cached results by invalidating the cache through
// FlushMapCache() and FlushMapCacheEntry().
func HaveMapType(mt ebpf.MapType) error {
	if mt >= ebpf.MaxMapType {
		return internal.ErrNotSupported
	}

	// For now a feature probe for StructOpts can't be supported by the API
	// This means we cannot really tell if StructOpts is supported by the current kernel
	if mt == ebpf.StructOpts {
		return ErrInconclusive
	}

	mapCache.RLock()
	err, ok := mapCache.mapTypes[mt]
	mapCache.RUnlock()
	if ok {
		return err
	}

	attr := createMapTypeAttr(mt)
	_, err = internal.BPFMapCreate(attr)

	// For nested and storage map types we accept EBADF as indicator these maps are supported
	if errors.Is(err, unix.EBADF) {
		if isMapOfMaps(mt) || isStorageMap(mt) {
			err = nil
		}
	}

	// still needs policy for EPERM
	if err != nil {
		fmt.Println(err)
		err = internal.ErrNotSupported
	}

	mapCache.Lock()
	mapCache.mapTypes[mt] = err
	mapCache.Unlock()

	return err
}

func isMapOfMaps(mt ebpf.MapType) bool {
	switch mt {
	case ebpf.ArrayOfMaps, ebpf.HashOfMaps:
		return true
	}
	return false
}

func isStorageMap(mt ebpf.MapType) bool {
	switch mt {
	case ebpf.SkStorage, ebpf.InodeStorage, ebpf.TaskStorage:
		return true
	}

	return false
}
