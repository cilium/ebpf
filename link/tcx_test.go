package link

import (
	"fmt"
	"math"
	"net"
	"testing"

	qt "github.com/frankban/quicktest"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"
)

func TestAttachTCX(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.6", "TCX link")

	prog := mustLoadProgram(t, ebpf.SchedCLS, ebpf.AttachNone, "")
	link, _ := mustAttachTCX(t, prog, ebpf.AttachTCXIngress)

	testLink(t, link, prog)
}

func TestTCXAnchor(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.6", "TCX link")

	a := mustLoadProgram(t, ebpf.SchedCLS, ebpf.AttachNone, "")
	b := mustLoadProgram(t, ebpf.SchedCLS, ebpf.AttachNone, "")

	linkA, iface := mustAttachTCX(t, a, ebpf.AttachTCXEgress)

	programInfo, err := a.Info()
	qt.Assert(t, err, qt.IsNil)
	programID, _ := programInfo.ID()

	linkInfo, err := linkA.Info()
	qt.Assert(t, err, qt.IsNil)
	linkID := linkInfo.ID

	for _, anchor := range []Anchor{
		Head(),
		Tail(),
		BeforeProgram(a),
		BeforeProgramByID(programID),
		AfterLink(linkA),
		AfterLinkByID(linkID),
	} {
		t.Run(fmt.Sprintf("%T", anchor), func(t *testing.T) {
			linkB, err := AttachTCX(TCXOptions{
				Program:   b,
				Attach:    ebpf.AttachTCXEgress,
				Interface: iface,
				Anchor:    anchor,
			})
			qt.Assert(t, err, qt.IsNil)
			qt.Assert(t, linkB.Close(), qt.IsNil)
		})
	}
}

func TestTCXExpectedRevision(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.6", "TCX link")

	iface, err := net.InterfaceByName("lo")
	qt.Assert(t, err, qt.IsNil)

	_, err = AttachTCX(TCXOptions{
		Program:          mustLoadProgram(t, ebpf.SchedCLS, ebpf.AttachNone, ""),
		Attach:           ebpf.AttachTCXEgress,
		Interface:        iface.Index,
		ExpectedRevision: math.MaxUint64,
	})
	qt.Assert(t, err, qt.ErrorIs, unix.ESTALE)
}

func mustAttachTCX(tb testing.TB, prog *ebpf.Program, attachType ebpf.AttachType) (Link, int) {
	iface, err := net.InterfaceByName("lo")
	qt.Assert(tb, err, qt.IsNil)

	link, err := AttachTCX(TCXOptions{
		Program:   prog,
		Attach:    attachType,
		Interface: iface.Index,
	})
	qt.Assert(tb, err, qt.IsNil)
	tb.Cleanup(func() { qt.Assert(tb, link.Close(), qt.IsNil) })

	return link, iface.Index
}
