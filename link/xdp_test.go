//go:build !windows

package link

import (
	"math"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

const IfIndexLO = 1

func TestAttachXDP(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.9", "BPF_LINK_TYPE_XDP")

	prog := mustLoadProgram(t, ebpf.XDP, 0, "")

	_, err := AttachXDP(XDPOptions{
		Program:   prog,
		Interface: math.MaxInt,
	})
	qt.Assert(t, qt.IsNotNil(err))

	l, err := AttachXDP(XDPOptions{
		Program:   prog,
		Interface: IfIndexLO,
	})
	qt.Assert(t, qt.IsNil(err))

	info, err := l.Info()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(info.XDP().Ifindex, IfIndexLO))

	testLink(t, l, prog)
}
