package ebpf

import "github.com/cilium/ebpf/internal"

// unused at the moment
// might be useful for functions that eventually return entire overview of features
type Features struct {
	MapTypes map[MapType]error
}

var (
	mapTypeCache = make(map[MapType]error)
)

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
	if err, ok := mapTypeCache[mt]; ok {
		return err
	}

	// build create map attr for map type
	attr := probeMapTypeAttr(mt)

	// create map type
	// Do we care about deleting those objects?
	// Does this happen automatically once using process dies?
	_, err := bpfMapCreate(attr)

	// interpret kernel error as own error interface
	// obviously needs more than just the err != nil check
	if err != nil {
		err = internal.ErrNotSupported
	}

	// store result to cash
	mapTypeCache[mt] = err

	// return result
	return err
}
