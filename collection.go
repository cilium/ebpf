package ebpf

import (
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
)

// CollectionSpec describes a collection.
type CollectionSpec struct {
	Maps     map[string]*MapSpec
	Programs map[string]*ProgramSpec
}

// LoadCollectionSpec parse an object file and convert it to a collection
func LoadCollectionSpec(file string) (*CollectionSpec, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return LoadCollectionSpecFromReader(f)
}

// Collection is a collection of Programs and Maps associated
// with their symbols
type Collection struct {
	Programs map[string]*Program
	Maps     map[string]*Map
}

// NewCollection creates a Collection from a specification.
//
// Only maps referenced by at least one of the programs are initialized.
func NewCollection(spec *CollectionSpec) (*Collection, error) {
	maps := make(map[string]*Map)
	progs := make(map[string]*Program)
	for progName, progSpec := range spec.Programs {
		editor := Edit(&progSpec.Instructions)

		// Rewrite any Symbol which is a valid Map.
		for _, sym := range editor.ReferencedSymbols() {
			mapSpec, ok := spec.Maps[sym]
			if !ok {
				continue
			}

			m := maps[sym]
			if m == nil {
				var err error
				m, err = NewMap(mapSpec)
				if err != nil {
					return nil, errors.Wrapf(err, "map %s", sym)
				}
				maps[sym] = m
			}

			if err := editor.RewriteMap(sym, m); err != nil {
				return nil, errors.Wrapf(err, "program %s", progName)
			}
		}

		prog, err := NewProgram(progSpec)
		if err != nil {
			return nil, errors.Wrapf(err, "program %s", progName)
		}
		progs[progName] = prog
	}
	return &Collection{
		progs,
		maps,
	}, nil
}

// LoadCollection parses an object file and converts it to a collection.
func LoadCollection(file string) (*Collection, error) {
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		return nil, err
	}
	return NewCollection(spec)
}

// Close frees all maps and programs associated with the collection.
//
// The collection mustn't be used afterwards.
func (coll *Collection) Close() {
	for _, prog := range coll.Programs {
		prog.Close()
	}
	for _, m := range coll.Maps {
		m.Close()
	}
}

// Pin persits a Collection beyond the lifetime of the process that created it
//
// This requires bpffs to be mounted above fileName. See http://cilium.readthedocs.io/en/doc-1.0/kubernetes/install/#mounting-the-bpf-fs-optional
func (coll *Collection) Pin(dirName string, fileMode os.FileMode) error {
	err := mkdirIfNotExists(dirName, fileMode)
	if err != nil {
		return err
	}
	if len(coll.Maps) > 0 {
		mapPath := filepath.Join(dirName, "maps")
		err = mkdirIfNotExists(mapPath, fileMode)
		if err != nil {
			return err
		}
		for k, v := range coll.Maps {
			err := v.Pin(filepath.Join(mapPath, k))
			if err != nil {
				return errors.Wrapf(err, "map %s", k)
			}
		}
	}
	if len(coll.Programs) > 0 {
		progPath := filepath.Join(dirName, "programs")
		err = mkdirIfNotExists(progPath, fileMode)
		if err != nil {
			return err
		}
		for k, v := range coll.Programs {
			err = v.Pin(filepath.Join(progPath, k))
			if err != nil {
				return errors.Wrapf(err, "program %s", k)
			}
		}
	}
	return nil
}

func mkdirIfNotExists(dirName string, fileMode os.FileMode) error {
	_, err := os.Stat(dirName)
	if err != nil && os.IsNotExist(err) {
		err = os.Mkdir(dirName, fileMode)
	}
	if err != nil {
		return err
	}
	return nil
}

// LoadPinnedCollection loads a Collection from the pinned directory.
//
// Requires at least Linux 4.13, use LoadPinnedCollectionExplicit on
// earlier versions.
func LoadPinnedCollection(dirName string) (*Collection, error) {
	return loadCollection(
		dirName,
		func(_ string, path string) (*Map, error) {
			return LoadPinnedMap(path)
		},
		func(_ string, path string) (*Program, error) {
			return LoadPinnedProgram(path)
		},
	)
}

// LoadPinnedCollectionExplicit loads a Collection from the pinned directory with explicit parameters.
func LoadPinnedCollectionExplicit(dirName string, maps map[string]*MapSpec, progs map[string]ProgType) (*Collection, error) {
	return loadCollection(
		dirName,
		func(name string, path string) (*Map, error) {
			return LoadPinnedMapExplicit(path, maps[name])
		},
		func(name string, path string) (*Program, error) {
			return LoadPinnedProgramExplicit(path, progs[name])
		},
	)
}

func loadCollection(dirName string, loadMap func(string, string) (*Map, error), loadProgram func(string, string) (*Program, error)) (*Collection, error) {
	maps, err := readFileNames(filepath.Join(dirName, "maps"))
	if err != nil {
		return nil, err
	}
	progs, err := readFileNames(filepath.Join(dirName, "programs"))
	if err != nil {
		return nil, err
	}
	bpfColl := &Collection{
		Maps:     make(map[string]*Map),
		Programs: make(map[string]*Program),
	}
	for _, mf := range maps {
		name := filepath.Base(mf)
		m, err := loadMap(name, mf)
		if err != nil {
			return nil, errors.Wrapf(err, "map %s", name)
		}
		bpfColl.Maps[name] = m
	}
	for _, pf := range progs {
		name := filepath.Base(pf)
		prog, err := loadProgram(name, pf)
		if err != nil {
			return nil, errors.Wrapf(err, "program %s", name)
		}
		bpfColl.Programs[name] = prog
	}
	return bpfColl, nil
}

func readFileNames(dirName string) ([]string, error) {
	var fileNames []string
	files, err := ioutil.ReadDir(dirName)
	if err != nil && err != os.ErrNotExist {
		return nil, err
	}
	for _, fi := range files {
		fileNames = append(fileNames, fi.Name())
	}
	return fileNames, nil
}
