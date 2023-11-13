package link

import (
	"fmt"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"

	qt "github.com/frankban/quicktest"
)

func TestProgramAlter(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.13", "SkSKB type")

	prog := mustLoadProgram(t, ebpf.SkSKB, 0, "")

	var sockMap *ebpf.Map
	sockMap, err := ebpf.NewMap(&ebpf.MapSpec{
		Type:       ebpf.MapType(15), // BPF_MAP_TYPE_SOCKMAP
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer sockMap.Close()

	err = RawAttachProgram(RawAttachProgramOptions{
		Target:  sockMap.FD(),
		Program: prog,
		Attach:  ebpf.AttachSkSKBStreamParser,
	})
	if err != nil {
		t.Fatal(err)
	}

	err = RawDetachProgram(RawDetachProgramOptions{
		Target:  sockMap.FD(),
		Program: prog,
		Attach:  ebpf.AttachSkSKBStreamParser,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestRawAttachProgramAnchor(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.6", "attach anchor")

	iface, err := net.InterfaceByName("lo")
	qt.Assert(t, err, qt.IsNil)

	a := mustLoadProgram(t, ebpf.SchedCLS, 0, "")
	info, err := a.Info()
	qt.Assert(t, err, qt.IsNil)
	aID, _ := info.ID()

	err = RawAttachProgram(RawAttachProgramOptions{
		Target:  iface.Index,
		Program: a,
		Attach:  ebpf.AttachTCXIngress,
	})
	qt.Assert(t, err, qt.IsNil)
	defer RawDetachProgram(RawDetachProgramOptions{
		Target:  iface.Index,
		Program: a,
		Attach:  ebpf.AttachTCXIngress,
	})

	link, err := AttachTCX(TCXOptions{
		Interface: iface.Index,
		Program:   mustLoadProgram(t, ebpf.SchedCLS, 0, ""),
		Attach:    ebpf.AttachTCXIngress,
	})
	qt.Assert(t, err, qt.IsNil)
	defer link.Close()

	linkInfo, err := link.Info()
	qt.Assert(t, err, qt.IsNil)

	b := mustLoadProgram(t, ebpf.SchedCLS, 0, "")

	for _, anchor := range []Anchor{
		First(),
		Last(),
		AfterProgram(a),
		AfterProgramByID(aID),
		AfterLink(link),
		AfterLinkByID(linkInfo.ID),
	} {
		t.Run(fmt.Sprintf("%T", anchor), func(t *testing.T) {
			err := RawAttachProgram(RawAttachProgramOptions{
				Target:  iface.Index,
				Program: b,
				Attach:  ebpf.AttachTCXIngress,
				Anchor:  anchor,
			})
			qt.Assert(t, err, qt.IsNil)

			// Detach doesn't allow first or last anchor.
			if _, ok := anchor.(firstAnchor); ok {
				anchor = nil
			} else if _, ok := anchor.(lastAnchor); ok {
				anchor = nil
			}

			err = RawDetachProgram(RawDetachProgramOptions{
				Target:  iface.Index,
				Program: b,
				Attach:  ebpf.AttachTCXIngress,
				Anchor:  anchor,
			})
			qt.Assert(t, err, qt.IsNil)
		})
	}

	// Check that legacy replacement with a program works.
	err = RawAttachProgram(RawAttachProgramOptions{
		Target:  iface.Index,
		Program: b,
		Attach:  ebpf.AttachTCXIngress,
		Anchor:  ReplaceProgram(a),
	})
	qt.Assert(t, err, qt.IsNil)

	err = RawDetachProgram(RawDetachProgramOptions{
		Target:  iface.Index,
		Program: b,
		Attach:  ebpf.AttachTCXIngress,
	})
	qt.Assert(t, err, qt.IsNil)
}
