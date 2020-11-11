package link

import (
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
)

type SkLookupInfo struct {
	ID      ID
	Program ebpf.ProgramID
}

type SkLookupLink struct {
	*RawLink
}

func AttachSkLookup(netnsFD int, prog *ebpf.Program) (*SkLookupLink, error) {
	link, err := AttachRawLink(RawLinkOptions{
		Target:  netnsFD,
		Program: prog,
		Attach:  ebpf.AttachSkLookup,
	})
	if err != nil {
		return nil, err
	}

	return &SkLookupLink{link}, nil
}

func LoadPinnedSkLookup(fileName string) (*SkLookupLink, error) {
	link, err := LoadPinnedRawLink(fileName)
	if err != nil {
		return nil, fmt.Errorf("pinned sk_lookup: %s", err)
	}

	return &SkLookupLink{link}, nil
}

// struct bpf_link_info for sk_lookup programs.
type bpfSkLookupLinkInfo struct {
	typ         uint32
	id          uint32
	prog_id     uint32
	netns_ino   uint32
	attach_type uint32
}

// Info returns information about the link.
func (skl *SkLookupLink) Info() (*SkLookupInfo, error) {
	var info bpfSkLookupLinkInfo
	err := internal.BPFObjGetInfoByFD(skl.fd, unsafe.Pointer(&info), unsafe.Sizeof(info))
	if err != nil {
		return nil, fmt.Errorf("sk_lookup info: %s", err)
	}

	return &SkLookupInfo{
		ID:      ID(info.id),
		Program: ebpf.ProgramID(info.prog_id),
	}, nil
}
