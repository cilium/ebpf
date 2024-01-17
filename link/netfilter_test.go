package link

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

const (
	NFPROTO_IPV4      = 0x2
	NF_INET_LOCAL_OUT = 0x3
)

func TestAttachNetfilter(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.4", "BPF_LINK_TYPE_NETFILTER")

	prog := mustLoadProgram(t, ebpf.Netfilter, ebpf.AttachNetfilter, "")

	l, err := AttachNetfilter(NetfilterOptions{
		Program:        prog,
		ProtocolFamily: NFPROTO_IPV4,
		HookNumber:     NF_INET_LOCAL_OUT,
		Priority:       -128,
	})
	if err != nil {
		t.Fatal(err)
	}

	testLink(t, l, prog)
}
