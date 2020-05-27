package raw_tracepoints

import (
	"unsafe"

	"github.com/cilium/ebpf/internal"
)

const (
	rawTracepointOpen = 17
)

type bpfRawTracepointOpenAttr struct {
	name internal.Pointer
	fd   uint32
}

func bpfRawTracepointOpen(attr *bpfRawTracepointOpenAttr) error {
	_, err := internal.BPF(rawTracepointOpen, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}
