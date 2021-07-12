package features

import (
	"errors"
	"os"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

var ErrInconclusive = errors.New("probe was inconclusive")

type MapCache struct {
	sync.Mutex
	mapTypes map[ebpf.MapType]error
}

var (
	mapCache MapCache
)

func init() {
	mapCache.mapTypes = make(map[ebpf.MapType]error)

	// For now a feature probe for StructOpts can't be supported by the API
	// This means we cannot really tell if StructOpts is supported by the current kernel
	mapCache.mapTypes[ebpf.StructOpts] = ErrInconclusive
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
		// keySize needs to be sizeof(struct{u32 + u64}) = 12 (+ padding = 16)
		// by using unsafe.Sizeof(int) we are making sure that this works on 32bit and 64bit archs
		// checked at allocation time
		var align int
		keySize = uint32(8 + unsafe.Sizeof(align))
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
		maxEntries = uint32(os.Getpagesize())
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
func HaveMapType(mt ebpf.MapType) error {
	if mt >= ebpf.MaxMapType {
		return internal.ErrNotSupported
	}

	mapCache.Lock()
	defer mapCache.Unlock()
	err, ok := mapCache.mapTypes[mt]
	if ok {
		return err
	}

	_, err = internal.BPFMapCreate(createMapTypeAttr(mt))

	// For nested and storage map types we accept EBADF as indicator that these maps are supported
	if errors.Is(err, unix.EBADF) {
		if isMapOfMaps(mt) || isStorageMap(mt) {
			err = nil
		}
	}

	if err != nil {
		err = internal.ErrNotSupported
	}

	mapCache.mapTypes[mt] = err

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
