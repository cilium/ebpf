package ebpf

import "github.com/cilium/ebpf/internal"

func guessNonExistentKey(_ *Map) ([]byte, error) {
	return nil, internal.ErrNotSupportedOnOS
}
