package ebpf

import "github.com/cilium/ebpf/internal/unix"

// RemoveMemlockRlimit removes the limit on the amount of memory
// the process can lock into RAM. Returns a function that restores
// the limit to its previous value. This is not required to load
// eBPF resources on kernel versions 5.11+ due to the introduction
// of cgroup-bases memory accounting.
func RemoveMemlockRlimit() (func() error, error) {
	return unix.RemoveMemlockRlimit()
}
