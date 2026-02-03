//go:build !windows

package link

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestAttachNetfilter(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.4", "BPF_LINK_TYPE_NETFILTER")

	prog := mustLoadProgram(t, ebpf.Netfilter, ebpf.AttachNetfilter, "")

	l, err := AttachNetfilter(NetfilterOptions{
		Program:        prog,
		ProtocolFamily: NetfilterProtoIPv4,
		Hook:           NetfilterInetLocalOut,
		Priority:       -128,
	})
	if err != nil {
		t.Fatal(err)
	}

	info, err := l.Info()
	if err != nil {
		t.Fatal(err)
	}
	nfInfo := info.Netfilter()
	qt.Assert(t, qt.Equals(nfInfo.ProtocolFamily, NetfilterProtoIPv4))
	qt.Assert(t, qt.Equals(nfInfo.Hook, NetfilterInetLocalOut))
	qt.Assert(t, qt.Equals(nfInfo.Priority, -128))

	testLink(t, l, prog)
}
