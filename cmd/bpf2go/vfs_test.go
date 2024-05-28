package main

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/go-quicktest/qt"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestVfsAdd(t *testing.T) {
	const (
		modPpAlgorithm     = "github.com/piedpiper/algorithm"
		modPpPiperchat     = "github.com/piedpiper/piperchat"
		modHooliXyz        = "github.com/hooli/xyz"
		modHooliXyzNucleus = "github.com/hooli/xyz/nucleus"
	)
	modPath := func(name string) string {
		return "home/hendricks/go/mod/pkg/" + name + "@v1"
	}
	fs := fstest.MapFS{
		modPath(modPpAlgorithm):             &fstest.MapFile{Mode: fs.ModeDir},
		modPath(modPpPiperchat):             &fstest.MapFile{Mode: fs.ModeDir},
		modPath(modHooliXyz) + "/README.md": &fstest.MapFile{},
		modPath(modHooliXyz) + "/internal":  &fstest.MapFile{Mode: fs.ModeDir},
		modPath(modHooliXyz) + "/nucleus":   &fstest.MapFile{Mode: fs.ModeDir}, // CONFLICT!
		modPath(modHooliXyzNucleus):         &fstest.MapFile{Mode: fs.ModeDir},
	}
	hooliVfs := vfsItem{
		Type: vfsDirectory, Contents: []vfsItem{{
			Name: "github.com", Type: vfsDirectory, Contents: []vfsItem{{
				Name: "hooli", Type: vfsDirectory, Contents: []vfsItem{{
					Name: "xyz", Type: vfsDirectory, Contents: []vfsItem{
						{Name: "README.md", Type: vfsFile, ExternalContents: modPath(modHooliXyz) + "/README.md"},
						{Name: "internal", Type: vfsDirectoryRemap, ExternalContents: modPath(modHooliXyz) + "/internal"},
						{Name: "nucleus", Type: vfsDirectoryRemap, ExternalContents: modPath(modHooliXyzNucleus)},
					},
				}},
			}},
		}},
	}
	type mapping struct{ vpath, path string }
	for _, item := range []struct {
		label string
		m     []mapping
		res   vfsItem
	}{
		{label: "nonoverlap", m: []mapping{
			{vpath: modPpAlgorithm, path: modPath(modPpAlgorithm)},
			{vpath: modPpPiperchat, path: modPath(modPpPiperchat)},
		}, res: vfsItem{
			Type: vfsDirectory, Contents: []vfsItem{{
				Name: "github.com", Type: vfsDirectory, Contents: []vfsItem{{
					Name: "piedpiper", Type: vfsDirectory, Contents: []vfsItem{
						{Name: "algorithm", Type: vfsDirectoryRemap, ExternalContents: modPath(modPpAlgorithm)},
						{Name: "piperchat", Type: vfsDirectoryRemap, ExternalContents: modPath(modPpPiperchat)},
					},
				}},
			}},
		}},
		{label: "overlap", m: []mapping{
			{vpath: modHooliXyz, path: modPath(modHooliXyz)},
			{vpath: modHooliXyzNucleus, path: modPath(modHooliXyzNucleus)},
		}, res: hooliVfs},
		{label: "overlapOtherOrder", m: []mapping{
			{vpath: modHooliXyzNucleus, path: modPath(modHooliXyzNucleus)},
			{vpath: modHooliXyz, path: modPath(modHooliXyz)},
		}, res: hooliVfs},
	} {
		t.Run(item.label, func(t *testing.T) {
			root := vfsItem{Type: vfsDirectory}
			for _, m := range item.m {
				qt.Assert(t, qt.IsNil(testVfsAdd(&root, m.vpath, m.path, fs)))
			}
			qt.Assert(t, qt.CmpEquals(root, item.res, cmpopts.IgnoreUnexported(vfsItem{}), cmpopts.SortSlices(func(i, j vfsItem) bool {
				return i.Name < j.Name
			})))
		})
	}
}

func testVfsAdd(root *vfsItem, vpath, dir string, fs fs.FS) error {
	return root.vfsAdd(vpath, dir, vfsDirectoryRemap, len(vpath), fs)
}
