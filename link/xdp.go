package link

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
)

// XDPAttachFlags represents how XDP program will be attached to interface.
type XDPAttachFlags uint32

const (
	// XDPGenericMode (SKB) links XDP BPF program for drivers which do
	// not yet support native XDP.
	XDPGenericMode XDPAttachFlags = 1 << (iota + 1)
	// XDPDriverMode links XDP BPF program into the driver’s receive path.
	XDPDriverMode
	// XDPOffloadMode offloads the entire XDP BPF program into hardware.
	XDPOffloadMode
)

type XDPOptions struct {
	// Program must be an XDP BPF program.
	Program *ebpf.Program
	// Interface is string name of interface or index (int)
	// to attach program to.
	Interface interface{}
	// Flags must match the attach flag of XDP.
	//
	// Only one XDP mode should be set, without flag defaults
	// to driver/generic mode (best effort).
	Flags XDPAttachFlags
}

// AttachXDP links an XDP BPF program to an XDP hook.
func AttachXDP(opts XDPOptions) (Link, error) {
	if t := opts.Program.Type(); t != ebpf.XDP {
		return nil, fmt.Errorf("invalid program type %s, expected XDP", t)
	}

	var IfIndex int
	switch value := opts.Interface.(type) {
	case string:
		ifce, err := net.InterfaceByName(value)
		if err != nil {
			return nil, err
		}
		IfIndex = ifce.Index
	case int:
		IfIndex = value
	default:
		return nil, fmt.Errorf("invalid interface value")
	}

	rawLink, err := AttachRawLink(RawLinkOptions{
		Program: opts.Program,
		Attach:  ebpf.AttachXDP,
		Target:  IfIndex,
		Flags:   uint32(opts.Flags),
	})

	return rawLink, err
}
