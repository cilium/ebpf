package sys

import "github.com/cilium/ebpf/internal/unix"

type MapFlags uint32

const (
	BPF_F_NO_PREALLOC MapFlags = unix.BPF_F_NO_PREALLOC
	BPF_F_RDONLY_PROG MapFlags = unix.BPF_F_RDONLY_PROG
	BPF_F_WRONLY_PROG MapFlags = unix.BPF_F_WRONLY_PROG
	BPF_F_MMAPABLE    MapFlags = unix.BPF_F_MMAPABLE
	BPF_F_INNER_MAP   MapFlags = unix.BPF_F_INNER_MAP
)
