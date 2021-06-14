package ebpf

import (
	"sync"

	"github.com/cilium/ebpf/internal"
)

type MapCache struct {
	mu       sync.RWMutex
	mapTypes map[MapType]error
}

var (
	mc MapCache
)

func init() {
	mc.mapTypes = make(map[MapType]error)
}

func probeMapTypeAttr(mt MapType) *bpfMapCreateAttr {
	var keySize, valueSize, maxEntries, flags uint32

	// switch on map types to generate correct bpfMapCreateAttr
	// inspiration from
	// https://sourcegraph.com/github.com/torvalds/linux/-/blob/tools/lib/bpf/libbpf_probes.c#L200
	switch mt {
	default:
		keySize = 4
		valueSize = 4
		maxEntries = 1
	}

	return &bpfMapCreateAttr{
		mapType:    mt,
		keySize:    keySize,
		valueSize:  valueSize,
		maxEntries: maxEntries,
		flags:      flags,
	}

}

func ProbeMapType(mt MapType) error {
	// make sure to bound Map types
	// MaxMapType new value in enum, easier to handle than making sure
	// we are checking the last value in the enum (which could eventually change)
	if mt >= MaxMapType {
		return internal.ErrNotSupported
	}

	mc.mu.RLock()
	if err, ok := mc.mapTypes[mt]; ok {
		defer mc.mu.RUnlock()
		return err
	}
	mc.mu.RUnlock()

	attr := probeMapTypeAttr(mt)
	_, err := bpfMapCreate(attr)

	// interpret kernel error as own error interface
	// obviously needs more than just the err != nil check
	if err != nil {
		err = internal.ErrNotSupported
	}

	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.mapTypes[mt] = err

	return err
}
