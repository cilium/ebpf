package link

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/xerrors"
)

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
		if !xerrors.Is(err, ErrNotSupported) {
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
