package link

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestRawLink(t *testing.T) {
	cgroup, prog, cleanup := mustCgroupFixtures(t)
	defer cleanup()

	link, err := AttachRawLink(RawLinkOptions{
		Target:  int(cgroup.Fd()),
		Program: prog,
		Attach:  ebpf.AttachCGroupInetEgress,
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create raw link:", err)
	}

	testLink(t, link, testLinkOptions{
		prog: prog,
		loadPinned: func(f string) (Link, error) {
			return LoadPinnedRawLink(f)
		},
	})
}

func mustCgroupFixtures(t *testing.T) (*os.File, *ebpf.Program, func()) {
	t.Helper()

	testutils.SkipIfNotSupported(t, haveProgAttach())

	prog := mustCgroupEgressProgram(t)
	cgdir, err := ioutil.TempDir("/sys/fs/cgroup/unified", "ebpf-link")
	if err != nil {
		prog.Close()
		t.Fatal("Can't create cgroupv2:", err)
	}

	cgroup, err := os.Open(cgdir)
	if err != nil {
		prog.Close()
		os.Remove(cgdir)
		t.Fatal(err)
	}

	return cgroup, prog, func() {
		prog.Close()
		cgroup.Close()
		os.Remove(cgdir)
	}
}

func mustCgroupEgressProgram(t *testing.T) *ebpf.Program {
	t.Helper()

	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:       ebpf.CGroupSKB,
		AttachType: ebpf.AttachCGroupInetEgress,
		License:    "MIT",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return prog
}

type testLinkOptions struct {
	prog       *ebpf.Program
	loadPinned func(string) (Link, error)
}

func testLink(t *testing.T, link Link, opts testLinkOptions) {
	t.Helper()

	tmp, err := ioutil.TempDir("/sys/fs/bpf", "ebpf-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	path := filepath.Join(tmp, "link")
	err = link.Pin(path)
	if err == ErrNotSupported {
		t.Errorf("%T.Pin returns unwrapped ErrNotSupported", link)
	}

	if opts.loadPinned == nil {
		if !errors.Is(err, ErrNotSupported) {
			t.Errorf("%T.Pin doesn't return ErrNotSupported: %s", link, err)
		}
	} else {
		if err != nil {
			t.Fatalf("Can't pin %T: %s", link, err)
		}

		link2, err := opts.loadPinned(path)
		if err != nil {
			t.Fatalf("Can't load pinned %T: %s", link, err)
		}
		link2.Close()

		if reflect.TypeOf(link) != reflect.TypeOf(link2) {
			t.Errorf("Loading a pinned %T returns a %T", link, link2)
		}
	}

	if err := link.Update(opts.prog); err != nil {
		t.Fatalf("%T.Update returns an error: %s", link, err)
	}

	func() {
		// Panicking is OK
		defer func() {
			recover()
		}()

		if err := link.Update(nil); err == nil {
			t.Fatalf("%T.Update accepts nil program", link)
		}
	}()

	if err := link.Close(); err != nil {
		t.Fatalf("%T.Close returns an error: %s", link, err)
	}
}
