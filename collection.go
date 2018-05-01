package ebpf

import (
	"io/ioutil"
	"os"
	"path"
)

// CollectionSpec describes a collection.
type CollectionSpec struct {
	Maps     map[string]*MapSpec
	Programs map[string]*ProgramSpec
}

// Collection is a collection of Programs and Maps associated
// with their symbols
type Collection struct {
	programs map[string]Program
	maps     map[string]Map
}

// NewCollection creates a Collection from a specification
func NewCollection(spec *CollectionSpec) (*Collection, error) {
	maps := make(map[string]Map)
	for k, spec := range spec.Maps {
		m, err := NewMap(spec)
		if err != nil {
			return nil, err
		}
		maps[k] = m
	}
	progs := make(map[string]Program)
	for k, spec := range spec.Programs {
		// Rewrite any Symbol which is a valid Map.
		for name := range spec.Refs {
			m, ok := maps[name]
			if !ok {
				continue
			}
			if err := spec.RewriteMap(name, m); err != nil {
				return nil, err
			}
		}
		prog, err := NewProgram(spec)
		if err != nil {
			return nil, err
		}
		progs[k] = prog
	}
	return &Collection{
		progs,
		maps,
	}, nil
}

// ForEachMap iterates over all the Maps in a Collection
func (coll *Collection) ForEachMap(fx func(string, Map)) {
	for k, v := range coll.maps {
		fx(k, v)
	}
}

// ForEachProgram iterates over all the Programs in a Collection
func (coll *Collection) ForEachProgram(fx func(string, Program)) {
	for k, v := range coll.programs {
		fx(k, v)
	}
}

// GetMapByName get a Map by its symbolic name
func (coll *Collection) GetMapByName(key string) (Map, bool) {
	v, ok := coll.maps[key]
	return v, ok
}

// GetProgramByName get a Program by its symbolic name
func (coll *Collection) GetProgramByName(key string) (Program, bool) {
	v, ok := coll.programs[key]
	return v, ok
}

// Pin persits a Collection beyond the lifetime of the process that created it
func (coll *Collection) Pin(dirName string, fileMode os.FileMode) error {
	err := mkdirIfNotExists(dirName, fileMode)
	if err != nil {
		return err
	}
	if len(coll.maps) > 0 {
		mapPath := path.Join(dirName, "maps")
		err = mkdirIfNotExists(mapPath, fileMode)
		if err != nil {
			return err
		}
		for k, v := range coll.maps {
			err := v.Pin(path.Join(mapPath, k))
			if err != nil {
				return err
			}
		}
	}
	if len(coll.programs) > 0 {
		progPath := path.Join(dirName, "programs")
		err = mkdirIfNotExists(progPath, fileMode)
		if err != nil {
			return err
		}
		for k, v := range coll.programs {
			err = v.Pin(path.Join(progPath, k))
			if err != nil {
				return err
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

// LoadCollection loads a Collection from the pinned directory
func LoadCollection(dirName string) (*Collection, error) {
	bpfColl := &Collection{
		maps:     make(map[string]Map),
		programs: make(map[string]Program),
	}
	mapsDir := path.Join(dirName, "maps")
	files, err := ioutil.ReadDir(mapsDir)
	if err != nil && err != os.ErrNotExist {
		return nil, err
	}
	if len(files) > 0 {
		for _, fi := range files {
			m, err := LoadMap(path.Join(mapsDir, fi.Name()))
			if err != nil {
				return nil, err
			}
			bpfColl.maps[fi.Name()] = m
		}
	}
	programDir := path.Join(dirName, "programs")
	files, err = ioutil.ReadDir(programDir)
	if err != nil && err != os.ErrNotExist {
		return nil, err
	}
	if len(files) > 0 {
		for _, fi := range files {
			p, err := LoadProgram(path.Join(programDir, fi.Name()))
			if err != nil {
				return nil, err
			}
			bpfColl.programs[fi.Name()] = p
		}
	}
	return bpfColl, nil
}

// NewCollectionFromFile parse an object file and convert it to a collection
func NewCollectionFromFile(file string) (*Collection, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	spec, err := NewCollectionSpecFromELF(f)
	if err != nil {
		return nil, err
	}
	return NewCollection(spec)
}
