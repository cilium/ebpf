package link

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/sys"
)

// XDPAttachTypeFlags represents the XDP attach type.
type XDPAttachTypeFlags uint32

const (
	// AttachTypeXDP tries to link as native XDP but in case
	// the driver does not support native XDP, it will automatically
	// fall back to generic XDP (default).
	AttachTypeXDP XDPAttachTypeFlags = iota
	// AttachTypeXDPGeneric links XDP BPF program for drivers which do not yet
	// support native XDP.
	AttachTypeXDPGeneric XDPAttachTypeFlags = 1 << (iota)
	// AttachTypeXDPDriver links XDP BPF program into the driver’s
	// receive path.
	AttachTypeXDPDriver
	// AttachTypeXDPOffload offloads the entire XDP BPF program into hardware.
	AttachTypeXDPOffload
)

type XDPOptions struct {
	// Program must be an XDP BPF program.
	Program *ebpf.Program
	// IfName is the interface name to attach to.
	IfName string
	// Flags must match the attach type of XDP.
	Flags XDPAttachTypeFlags
}

// AttachXDP links an XDP BPF program to an XDP hook.
func AttachXDP(opts XDPOptions) (Link, error) {
	if t := opts.Program.Type(); t != ebpf.XDP {
		return nil, fmt.Errorf("invalid program type %s, expected XDP", t)
	}

	if opts.Program.FD() < 0 {
		return nil, fmt.Errorf("invalid program %w", sys.ErrClosedFd)
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var ifIndex *int
	for _, iface := range ifaces {
		if iface.Name == opts.IfName {
			ifIndex = &iface.Index
			break
		}
	}
	if ifIndex == nil {
		return nil, fmt.Errorf("link %s not found", opts.IfName)
	}

	rawLink, err := AttachRawLink(RawLinkOptions{
		Program: opts.Program,
		Attach:  ebpf.AttachXDP,
		Target:  *ifIndex,
		Flags:   uint32(opts.Flags),
	})

	return rawLink, err
}
