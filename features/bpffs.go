package features

import (
	"errors"

	"github.com/cilium/ebpf/bpffs"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

func HaveBPFToken(path string) error {
	return haveBPFToken(internal.WithBpffs(path))
}

var haveBPFToken = internal.NewFeatureTest("CREATE_BPF_TOKEN",
	func(opts ...internal.FeatureTestOption) error {
		o := internal.BuildOptions(opts...)
		bfs, err := bpffs.NewBPFFSFromPath(o.BpffsMountPath)
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) {
			return internal.ErrNotSupported
		}

		_, err = bfs.Token()
		if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EPERM) {
			return internal.ErrNotSupported
		}
		return err
	},
	"6.9",
)
