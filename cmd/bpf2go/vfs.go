package main

import (
	"encoding/json"
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// vfs is LLVM virtual file system parsed from a file
//
// In a nutshell, it is a tree of "directory" nodes with leafs being
// either "file" (a reference to file) or "directory-remap" (a reference
// to directory).
//
// https://github.com/llvm/llvm-project/blob/llvmorg-18.1.0/llvm/include/llvm/Support/VirtualFileSystem.h#L637
type vfs struct {
	Version       int       `json:"version"`
	CaseSensitive bool      `json:"case-sensitive"`
	Roots         []vfsItem `json:"roots"`
}

type vfsItem struct {
	Name             string      `json:"name"`
	Type             vfsItemType `json:"type"`
	Contents         []vfsItem   `json:"contents,omitempty"`
	ExternalContents string      `json:"external-contents,omitempty"`
}

type vfsItemType string

const (
	vfsFile      vfsItemType = "file"
	vfsDirectory vfsItemType = "directory"
)

func (vi *vfsItem) addDir(path string) (*vfsItem, error) {
	for _, name := range strings.Split(path, "/") {
		idx := vi.index(name)
		if idx == -1 {
			idx = len(vi.Contents)
			vi.Contents = append(vi.Contents, vfsItem{Name: name, Type: vfsDirectory})
		}
		vi = &vi.Contents[idx]
		if vi.Type != vfsDirectory {
			return nil, fmt.Errorf("adding %q: non-directory object already exists", path)
		}
	}
	return vi, nil
}

func (vi *vfsItem) index(name string) int {
	return slices.IndexFunc(vi.Contents, func(item vfsItem) bool {
		return item.Name == name
	})
}

func persistVfs(vfs *vfs) (_ string, retErr error) {
	temp, err := os.CreateTemp("", "")
	if err != nil {
		return "", err
	}
	defer func() {
		temp.Close()
		if retErr != nil {
			os.Remove(temp.Name())
		}
	}()

	if err = json.NewEncoder(temp).Encode(vfs); err != nil {
		return "", err
	}

	return temp.Name(), nil
}

// vfsRootDir is the (virtual) directory where we mount go module sources
// for the C includes to pick them, e.g. "<vfsRootDir>/github.com/cilium/ebpf".
const vfsRootDir = "/.vfsoverlay.d"

// createVfs produces a vfs from a list of packages. It creates a
// (virtual) directory tree reflecting package import paths and adds
// links to header files. E.g. for github.com/foo/bar containing awesome.h:
//
//	github.com/
//	  foo/
//	    bar/
//	      awesome.h -> $HOME/go/pkg/mod/github.com/foo/bar@version/awesome.h
func createVfs(pkgs []*build.Package) (*vfs, error) {
	roots := [1]vfsItem{{Name: vfsRootDir, Type: vfsDirectory}}
	for _, pkg := range pkgs {
		var headers []vfsItem
		for _, h := range hfiles(pkg) {
			headers = append(headers, vfsItem{Name: h, Type: vfsFile,
				ExternalContents: filepath.Join(pkg.Dir, h)})
		}
		dir, err := roots[0].addDir(pkg.ImportPath)
		if err != nil {
			return nil, err
		}
		dir.Contents = headers // NB don't append inplace, same package could be imported twice
	}
	return &vfs{CaseSensitive: true, Roots: roots[:]}, nil
}
