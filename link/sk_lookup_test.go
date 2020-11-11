package link

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestSkLookup(t *testing.T) {
	prog := createSkLookupProgram()
	defer prog.Close()

	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer netns.Close()

	link, err := AttachSkLookup(int(netns.Fd()), prog)
	if err != nil {
		t.Fatal("Can't attach link:", err)
	}

	info, err := link.Info()
	if err != nil {
		t.Fatal("Can't get info:", err)
	}

	progID, err := prog.ID()
	if err != nil {
		t.Fatal("Can't get program ID:", err)
	}
	if info.Program != progID {
		t.Error("Link program ID doesn't match program ID")
	}

	testLink(t, link, testLinkOptions{
		prog: prog,
		loadPinned: func(fileName string) (Link, error) {
			return LoadPinnedSkLookup(fileName)
		},
	})
}

func createSkLookupProgram() *ebpf.Program {
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
		panic(err)
	}
	return prog
}

func ExampleAttachSkLookup() {
	prog := createSkLookupProgram()
	defer prog.Close()

	// This can be a path to another netns as well.
	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		panic(err)
	}
	defer netns.Close()

	link, err := AttachSkLookup(int(netns.Fd()), prog)
	if err != nil {
		panic(err)
	}

	// The socket lookup program is now active until Close().
	link.Close()
}
