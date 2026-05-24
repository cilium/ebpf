//go:build linux

package examples

import "github.com/cilium/ebpf/rlimit"

func DocRlimit() {
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(err)
	}
}
