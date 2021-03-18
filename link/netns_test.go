package link

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestSkLookup(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "sk_lookup program")

	prog := mustCreateSkLookupProgram(t)

	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer netns.Close()

	link, err := AttachNetNs(int(netns.Fd()), prog)
	if err != nil {
		t.Fatal("Can't attach link:", err)
	}

	_, err = link.Info()
	if err != nil {
		t.Fatal("Info returns an error:", err)
	}

	testLink(t, link, testLinkOptions{
		prog: prog,
		loadPinned: func(fileName string, opts *ebpf.LoadPinOptions) (Link, error) {
			return LoadPinnedNetNs(fileName, opts)
		},
	})
}

func mustCreateSkLookupProgram(tb testing.TB) *ebpf.Program {
	tb.Helper()

	prog, err := createSkLookupProgram()
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { prog.Close() })

	return prog
}

func createSkLookupProgram() (*ebpf.Program, error) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.SkLookup,
		AttachType: ebpf.AttachSkLookup,
		License:    "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		return nil, err
	}
	return prog, nil
}

func ExampleAttachNetNs() {
	prog, err := createSkLookupProgram()
	if err != nil {
		panic(err)
	}
	defer prog.Close()

	// This can be a path to another netns as well.
	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		panic(err)
	}
	defer netns.Close()

	link, err := AttachNetNs(int(netns.Fd()), prog)
	if err != nil {
		panic(err)
	}

	// The socket lookup program is now active until Close().
	link.Close()
}
