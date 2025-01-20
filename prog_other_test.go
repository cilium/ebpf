//go:build !windows

package ebpf

import (
	"github.com/cilium/ebpf/asm"
)

const basicProgramType = SocketFilter
const xdpProgramType = XDP
const fnMapLookupElem = asm.FnMapLookupElem
