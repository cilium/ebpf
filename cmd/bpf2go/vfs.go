package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

// vfs is LLVM virtual file system parsed from YAML file
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

	// specificity is used internally to resolve conflicts
	//
	// We populate vfs from go modules. Surprisingly, module file
	// trees may overlap, e.g. "github.com/aws/aws-sdk-go-v2" and
	// "github.com/aws/aws-sdk-go-v2/internal/endpoints/v2".
	specificity int
}

type vfsItemType string

const (
	vfsFile           vfsItemType = "file"
	vfsDirectory      vfsItemType = "directory"
	vfsDirectoryRemap vfsItemType = "directory-remap"
)

// vfsAdd adds "directory-remap" entry for dir under vpath
func vfsAdd(root *vfsItem, vpath, dir string) error {
	return root.vfsAdd(vpath, dir, vfsDirectoryRemap, len(vpath), defaultFS{})
}

type defaultFS struct{}

func (defaultFS) Open(name string) (fs.File, error) {
	return os.Open(name)
}

func (defaultFS) Stat(name string) (fs.FileInfo, error) {
	return os.Stat(name)
}

func (vi *vfsItem) vfsAdd(vpath, path string, typ vfsItemType, specificity int, fs fs.FS) error {
	for _, name := range strings.Split(vpath, "/") {
		if name == "" {
			continue
		}
		idx := vi.index(name)
		if idx == -1 {
			switch vi.Type {
			case vfsDirectoryRemap:
				newItem := vfsItem{Name: vi.Name, Type: vfsDirectory}
				if err := vfsPopulateFromDir(&newItem, vi.ExternalContents, vi.specificity, fs); err != nil {
					return err
				}
				*vi, idx = newItem, newItem.index(name)
			case vfsFile:
				vi.Type, vi.ExternalContents = vfsDirectory, ""
			}
			if idx == -1 {
				idx = len(vi.Contents)
				vi.Contents = append(vi.Contents, vfsItem{Name: name, Type: vfsDirectory})
			}
		}
		vi = &vi.Contents[idx]
	}
	switch vi.Type {
	case vfsDirectory:
		if len(vi.Contents) == 0 {
			vi.Type, vi.ExternalContents, vi.specificity = typ, path, specificity
			return nil
		}
		if typ == vfsFile {
			return nil
		}
		return vfsPopulateFromDir(vi, path, specificity, fs)
	case vfsDirectoryRemap, vfsFile:
		if vi.specificity <= specificity {
			vi.Type, vi.ExternalContents, vi.specificity = typ, path, specificity
		}
	}
	return nil
}

func vfsPopulateFromDir(vi *vfsItem, dir string, specificity int, fsys fs.FS) error {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		info, err := fs.Stat(fsys, path) // follows symlinks
		if err != nil {
			return err
		}
		typ := vfsFile
		if info.Mode().IsDir() {
			typ = vfsDirectoryRemap
		}
		if err := vi.vfsAdd(entry.Name(), path, typ, specificity, fsys); err != nil {
			return err
		}
	}
	return nil
}

func (vi *vfsItem) index(name string) int {
	return slices.IndexFunc(vi.Contents, func(item vfsItem) bool {
		return item.Name == name
	})
}

// persistVfs stores vfs in user cache dir under a path derived from
// id; the file should stay around for the benefit of a language
// server / IDE
func persistVfs(id [sha256.Size]byte, vfs *vfs) (string, error) {
	idHex := hex.EncodeToString(id[:])
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(cacheDir, "bpf2go", "llvm-overlay", idHex[:2])
	name := filepath.Join(dir, idHex[2:])
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	tempName, err := persistVfsTemp(dir, vfs)
	if err != nil {
		return "", err
	}
	if err := os.Rename(tempName, name); err != nil {
		_ = os.Remove(tempName)
		return "", err
	}
	return name, nil
}

func persistVfsTemp(dir string, vfs *vfs) (string, error) {
	temp, err := os.CreateTemp(dir, "tmp")
	if err != nil {
		return "", err
	}
	enc := json.NewEncoder(temp)
	err = enc.Encode(vfs)
	_ = temp.Close()
	if err != nil {
		_ = os.Remove(temp.Name())
		return "", err
	}
	return temp.Name(), nil
}

// mod describes go module as returned by `go list -json -m`
type mod struct {
	Path, Dir string
	Indirect  bool
}

func listMods(dir string, args ...string) ([]mod, error) {
	cmd := exec.Command("go", append([]string{"list", "-json", "-m"}, args...)...)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}
	return parseMods(bytes.NewReader(out))
}

func parseMods(r io.Reader) ([]mod, error) {
	var res []mod
	dec := json.NewDecoder(r)
	for {
		var mod mod

		err := dec.Decode(&mod)
		if err == io.EOF {
			return res, nil
		}
		if err != nil {
			return nil, err
		}

		res = append(res, mod)
	}
}

// vfsRootDir is the (virtual) directory where we mount go module sources
// for the C includes to pick them, e.g. "<vfsRootDir>/github.com/cilium/ebpf".
const vfsRootDir = "/.vfsoverlay.d"

func createVfs(mods []mod) (*vfs, error) {
	roots := [1]vfsItem{{Name: vfsRootDir, Type: vfsDirectory}}
	for _, m := range mods {
		if m.Dir == "" {
			return nil, fmt.Errorf("%s is missing locally: consider 'go mod download'", m.Path)
		}
		if err := vfsAdd(&roots[0], m.Path, m.Dir); err != nil {
			return nil, err
		}
	}
	return &vfs{CaseSensitive: true, Roots: roots[:]}, nil
}
