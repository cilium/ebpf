package link

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/testutils/testmain"
	"github.com/cilium/ebpf/internal/unix"
)

func TestMain(m *testing.M) {
	testmain.Run(m)
}

func TestRawLink(t *testing.T) {
	link, prog := newRawLink(t)

	info, err := link.Info()
	if err != nil {
		t.Fatal("Can't get link info:", err)
	}

	pi, err := prog.Info()
	if err != nil {
		t.Fatal("Can't get program info:", err)
	}

	progID, ok := pi.ID()
	if !ok {
		t.Fatal("Program ID not available in program info")
	}

	if info.Program != progID {
		t.Error("Link program ID doesn't match program ID")
	}

	testLink(t, link, prog)
}

func TestUnpinRawLink(t *testing.T) {
	link, _ := newPinnedRawLink(t)

	qt.Assert(t, qt.IsTrue(link.IsPinned()))

	if err := link.Unpin(); err != nil {
		t.Fatal(err)
	}

	qt.Assert(t, qt.IsFalse(link.IsPinned()))
}

func TestRawLinkLoadPinnedWithOptions(t *testing.T) {
	link, path := newPinnedRawLink(t)
	defer link.Close()

	qt.Assert(t, qt.IsTrue(link.IsPinned()))

	// It seems like the kernel ignores BPF_F_RDONLY when updating a link,
	// so we can't test this.
	_, err := loadPinnedRawLink(path, &ebpf.LoadPinOptions{
		Flags: math.MaxUint32,
	})
	if !errors.Is(err, unix.EINVAL) {
		t.Fatal("Invalid flags don't trigger an error:", err)
	}
}

func TestIterator(t *testing.T) {
	tLink, _ := newPinnedRawLink(t)
	tLinkInfo, err := tLink.Info()
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't get original link info:", err)
	}

	it := new(Iterator)
	defer it.Close()

	prev := it.ID
	var foundLink Link
	for it.Next() {
		// Iterate all loaded links.
		if it.Link == nil {
			t.Fatal("Next doesn't assign link")
		}
		if it.ID == prev {
			t.Fatal("Iterator doesn't advance ID")
		}
		prev = it.ID
		if it.ID == tLinkInfo.ID {
			foundLink = it.Take()
		}
	}
	if err := it.Err(); err != nil {
		t.Fatal("Iteration returned an error:", err)
	}
	if it.Link != nil {
		t.Fatal("Next doesn't clean up link on last iteration")
	}
	if prev != it.ID {
		t.Fatal("Next changes ID on last iteration")
	}
	if foundLink == nil {
		t.Fatal("Original link not found")
	}
	defer foundLink.Close()
	// Confirm that we found the original link.
	info, err := foundLink.Info()
	if err != nil {
		t.Fatal("Can't get link info:", err)
	}
	if info.ID != tLinkInfo.ID {
		t.Fatal("Found link has wrong ID")
	}

}

func newPinnedRawLink(t *testing.T) (*RawLink, string) {
	t.Helper()

	link, _ := newRawLink(t)

	path := filepath.Join(testutils.TempBPFFS(t), "link")
	err := link.Pin(path)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	return link, path
}

func testLink(t *testing.T, link Link, prog *ebpf.Program) {
	t.Helper()

	tmp, err := os.MkdirTemp("/sys/fs/bpf", "ebpf-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	_, isRawLink := link.(*RawLink)

	t.Run("link/pinning", func(t *testing.T) {
		path := filepath.Join(tmp, "link")
		err = link.Pin(path)
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatalf("Can't pin %T: %s", link, err)
		}

		link2, err := LoadPinnedLink(path, nil)
		if err != nil {
			t.Fatalf("Can't load pinned %T: %s", link, err)
		}
		link2.Close()

		if !isRawLink && reflect.TypeOf(link) != reflect.TypeOf(link2) {
			t.Errorf("Loading a pinned %T returns a %T", link, link2)
		}

		_, err = LoadPinnedLink(path, &ebpf.LoadPinOptions{
			Flags: math.MaxUint32,
		})
		if !errors.Is(err, unix.EINVAL) {
			t.Errorf("Loading a pinned %T doesn't respect flags", link)
		}
	})

	t.Run("link/update", func(t *testing.T) {
		err := link.Update(prog)
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal("Update returns an error:", err)
		}

		func() {
			// Panicking is OK
			defer func() {
				_ = recover()
			}()

			if err := link.Update(nil); err == nil {
				t.Fatalf("%T.Update accepts nil program", link)
			}
		}()
	})

	testLinkArch(t, link)

	type FDer interface {
		FD() int
	}

	t.Run("from fd", func(t *testing.T) {
		fder, ok := link.(FDer)
		if !ok {
			t.Skip("Link doesn't allow retrieving FD")
		}

		// We need to dup the FD since NewLinkFromFD takes
		// ownership.
		dupFD, err := unix.FcntlInt(uintptr(fder.FD()), unix.F_DUPFD_CLOEXEC, 1)
		if err != nil {
			t.Fatal("Can't dup link FD:", err)
		}
		defer unix.Close(dupFD)

		newLink, err := NewFromFD(dupFD)
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal("Can't create new link from dup link FD:", err)
		}
		defer newLink.Close()

		if !isRawLink && reflect.TypeOf(newLink) != reflect.TypeOf(link) {
			t.Fatalf("Expected type %T, got %T", link, newLink)
		}
	})

	if err := link.Close(); err != nil {
		t.Fatalf("%T.Close returns an error: %s", link, err)
	}
}

func TestLoadWrongPin(t *testing.T) {
	l, p := newRawLink(t)

	tmp := testutils.TempBPFFS(t)
	ppath := filepath.Join(tmp, "prog")
	lpath := filepath.Join(tmp, "link")

	qt.Assert(t, qt.IsNil(p.Pin(ppath)))
	qt.Assert(t, qt.IsNil(l.Pin(lpath)))

	_, err := LoadPinnedLink(ppath, nil)
	qt.Assert(t, qt.IsNotNil(err))

	ll, err := LoadPinnedLink(lpath, nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(ll.Close()))
}
