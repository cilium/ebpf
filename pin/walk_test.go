package pin

import (
	"iter"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestWalkDir(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.13", "reading program objinfo")

	tmp := testutils.TempBPFFS(t)

	dir := filepath.Join(tmp, "dir")
	if !platform.IsWindows {
		// Windows doesn't have a BPF file system, so mkdir below fails.
		qt.Assert(t, qt.IsNil(os.Mkdir(dir, 0755)))
	}

	progPath := filepath.Join(tmp, "pinned_prog")
	mustPinnedProgram(t, progPath)
	mapPath := filepath.Join(dir, "pinned_map")
	mustPinnedMap(t, mapPath)

	next, stop := iter.Pull2(WalkDir(tmp, nil))
	defer stop()

	pin, err, ok := next()
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(reflect.TypeOf(pin.Object), reflect.TypeFor[*ebpf.Map]()))
	qt.Assert(t, qt.Equals(pin.Path, mapPath))

	pin, err, ok = next()
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(reflect.TypeOf(pin.Object), reflect.TypeFor[*ebpf.Program]()))
	qt.Assert(t, qt.Equals(pin.Path, progPath))

	_, _, ok = next()
	qt.Assert(t, qt.IsFalse(ok))

	t.Run("Not BPFFS", func(t *testing.T) {
		if platform.IsWindows {
			t.Skip("Windows does not have BPFFS")
		}

		next, stop := iter.Pull2(WalkDir("/", nil))
		defer stop()

		_, err, ok = next()
		qt.Assert(t, qt.IsTrue(ok))
		qt.Assert(t, qt.IsNotNil(err))

		_, _, ok = next()
		qt.Assert(t, qt.IsFalse(ok))
	})

}
