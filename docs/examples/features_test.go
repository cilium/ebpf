//go:build linux

package examples

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
)

func DocDetectXDP() {
	err := features.HaveProgramType(ebpf.XDP)
	if errors.Is(err, ebpf.ErrNotSupported) {
		fmt.Println("XDP program type is not supported")
		return
	}
	if errors.Is(err, ebpf.ErrNotPermitted) {
		fmt.Println("XDP program type is supported but permission denied")
		return
	}
	if err != nil {
		// Feature detection was inconclusive.
		//
		// Note: always log and investigate these errors! These can be caused
		// by verifier errors, etc. Unless stated otherwise, probes are
		// expected to be conclusive. Please file an issue if this is not the
		// case in your environment.
		panic(err)
	}

	fmt.Println("XDP program type is supported")
}
