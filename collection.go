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

// NewCollectionSpecFromFile parse an object file and convert it to a collection
func NewCollectionSpecFromFile(file string) (*CollectionSpec, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return NewCollectionSpecFromELF(f)
}

// Collection is a collection of Programs and Maps associated
// with their symbols
type Collection struct {
	programs map[string]*Program
	maps     map[string]*Map
}

// NewCollection creates a Collection from a specification
func NewCollection(spec *CollectionSpec) (*Collection, error) {
	maps := make(map[string]*Map)
	for k, spec := range spec.Maps {
		m, err := NewMap(spec)
		if err != nil {
			return nil, errors.Wrapf(err, "map %s", k)
		}
		maps[k] = m
	}
	progs := make(map[string]*Program)
	for k, spec := range spec.Programs {
		ed := Edit(&spec.Instructions)

		// Rewrite any Symbol which is a valid Map.
		for _, sym := range ed.ReferencedSymbols() {
			m, ok := maps[sym]
			if !ok {
				continue
			}
			if err := ed.RewriteMap(sym, m); err != nil {
				return nil, errors.Wrapf(err, "program %s", k)
			}
		}
		prog, err := NewProgram(spec)
		if err != nil {
			return nil, errors.Wrapf(err, "program %s", k)
		}
		progs[k] = prog
	}
	return &Collection{
		progs,
		maps,
	}, nil
}

// NewCollectionFromFile parses an object file and converts it to a collection.
func NewCollectionFromFile(file string) (*Collection, error) {
	spec, err := NewCollectionSpecFromFile(file)
	if err != nil {
		return nil, err
	}
	return NewCollection(spec)
}

// Close frees all maps and programs associated with the collection.
//
// The collection mustn't be used afterwards.
func (coll *Collection) Close() {
	for _, prog := range coll.programs {
		prog.Close()
	}
	for _, m := range coll.maps {
		m.Close()
	}
}

// ForEachMap iterates over all the Maps in a Collection
func (coll *Collection) ForEachMap(fx func(string, *Map)) {
	for k, v := range coll.maps {
		fx(k, v)
	}
}

// ForEachProgram iterates over all the Programs in a Collection
func (coll *Collection) ForEachProgram(fx func(string, *Program)) {
	for k, v := range coll.programs {
		fx(k, v)
	}
}

// GetMapByName get a Map by its symbolic name
func (coll *Collection) GetMapByName(key string) (*Map, bool) {
	v, ok := coll.maps[key]
	return v, ok
}

// GetProgramByName get a Program by its symbolic name
func (coll *Collection) GetProgramByName(key string) (*Program, bool) {
	v, ok := coll.programs[key]
	return v, ok
}

// Pin persits a Collection beyond the lifetime of the process that created it
//
// This requires bpffs to be mounted above fileName. See http://cilium.readthedocs.io/en/doc-1.0/kubernetes/install/#mounting-the-bpf-fs-optional
func (coll *Collection) Pin(dirName string, fileMode os.FileMode) error {
	err := mkdirIfNotExists(dirName, fileMode)
	if err != nil {
		return err
	}
	if len(coll.maps) > 0 {
		mapPath := filepath.Join(dirName, "maps")
		err = mkdirIfNotExists(mapPath, fileMode)
		if err != nil {
			return err
		}
		for k, v := range coll.maps {
			err := v.Pin(filepath.Join(mapPath, k))
			if err != nil {
				return errors.Wrapf(err, "map %s", k)
			}
		}
	}
	if len(coll.programs) > 0 {
		progPath := filepath.Join(dirName, "programs")
		err = mkdirIfNotExists(progPath, fileMode)
		if err != nil {
			return err
		}
		for k, v := range coll.programs {
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

// LoadCollection loads a Collection from the pinned directory.
//
// Requires at least Linux 4.13, use LoadCollectionExplicit on
// earlier versions.
func LoadCollection(dirName string) (*Collection, error) {
	return loadCollection(
		dirName,
		func(_ string, path string) (*Map, error) {
			return LoadMap(path)
		},
		func(_ string, path string) (*Program, error) {
			return LoadProgram(path)
		},
	)
}

// LoadCollectionExplicit loads a Collection from the pinned directory with explicit parameters.
func LoadCollectionExplicit(dirName string, maps map[string]*MapSpec, progs map[string]ProgType) (*Collection, error) {
	return loadCollection(
		dirName,
		func(name string, path string) (*Map, error) {
			return LoadMapExplicit(path, maps[name])
		},
		func(name string, path string) (*Program, error) {
			return LoadProgramExplicit(path, progs[name])
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
		maps:     make(map[string]*Map),
		programs: make(map[string]*Program),
	}
	for _, mf := range maps {
		name := filepath.Base(mf)
		m, err := loadMap(name, mf)
		if err != nil {
			return nil, errors.Wrapf(err, "map %s", name)
		}
		bpfColl.maps[name] = m
	}
	for _, pf := range progs {
		name := filepath.Base(pf)
		prog, err := loadProgram(name, pf)
		if err != nil {
			return nil, errors.Wrapf(err, "program %s", name)
		}
		bpfColl.programs[name] = prog
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
