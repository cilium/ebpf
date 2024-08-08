package link

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
)

func testLinkArch(t *testing.T, link Link) {
	// TODO(windows): Are there win specific behaviour we should test?
}

func newRawLink(t *testing.T) (*RawLink, *ebpf.Program) {
	c, err := ebpf.LoadCollection("../testdata/printk.sys")
	qt.Assert(t, qt.IsNil(err))
	defer c.Close()

	prog := c.DetachProgram("func")
	qt.Assert(t, qt.IsNotNil(prog))
	t.Cleanup(func() { prog.Close() })

	link, err := AttachRawLink(RawLinkOptions{
		Program: prog,
		Attach:  ebpf.AttachBind,
	})
	qt.Assert(t, qt.IsNil(err))
	t.Cleanup(func() { link.Close() })

	return link, prog
}
