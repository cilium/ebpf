package link

import (
	"github.com/cilium/ebpf"
)

// NetNsInfo contains metadata about a network namespace link.
type NetNsInfo struct {
	RawLinkInfo
}

// NetNsLink is a program attached to a network namespace.
type NetNsLink struct {
	*RawLink
}

// AttachSkLookup attaches a sk_lookup program to a network namespace.
func AttachSkLookup(ns int, prog *ebpf.Program) (*NetNsLink, error) {
	link, err := AttachRawLink(RawLinkOptions{
		Target:  ns,
		Program: prog,
		Attach:  ebpf.AttachSkLookup,
	})
	if err != nil {
		return nil, err
	}

	return &NetNsLink{link}, nil
}

// LoadPinnedNetNs loads a network namespace link from bpffs.
func LoadPinnedNetNs(fileName string) (*NetNsLink, error) {
	link, err := loadPinnedRawLink(fileName, NetNsType)
	if err != nil {
		return nil, err
	}

	return &NetNsLink{link}, nil
}

// Info returns information about the link.
func (nns *NetNsLink) Info() (*NetNsInfo, error) {
	info, err := nns.RawLink.Info()
	if err != nil {
		return nil, err
	}
	return &NetNsInfo{*info}, nil
}
