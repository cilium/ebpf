package pin

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal/testutils"
)

func TestWalkDir(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.10", "reading program fdinfo")

	tmp := testutils.TempBPFFS(t)
	dir := filepath.Join(tmp, "dir")
	qt.Assert(t, qt.IsNil(os.Mkdir(dir, 0755)))

	mustPinnedProgram(t, filepath.Join(tmp, "pinned_prog"))
	mustPinnedMap(t, filepath.Join(dir, "pinned_map"))

	entries := make(map[string]string)

	bpffn := func(path string, d fs.DirEntry, obj Pinner, err error) error {
		qt.Assert(t, qt.IsNil(err))

		if path == "." {
			return nil
		}

		switch obj.(type) {
		case *ebpf.Program:
			entries[path] = "prog"
		case *ebpf.Map:
			entries[path] = "map"
		default:
			entries[path] = ""
		}

		return nil
	}
	qt.Assert(t, qt.IsNil(WalkDir(tmp, bpffn)))

	qt.Assert(t, qt.DeepEquals(entries, map[string]string{
		"pinned_prog":    "prog",
		"dir":            "",
		"dir/pinned_map": "map",
	}))

	qt.Assert(t, qt.IsNotNil(WalkDir("/", nil)))
}
