package ebpf

import (
	"io"
	"io/ioutil"
	"os"
	"path"
)

// Collection is a collection of Programs and Maps associated
// with their symbols
type Collection struct {
	programMap map[string]Program
	mapMap     map[string]Map
}

// ForEachMap iterates over all the Maps in a Collection
func (coll *Collection) ForEachMap(fx func(string, Map)) {
	for k, v := range coll.mapMap {
		fx(k, v)
	}
}

// ForEachProgram iterates over all the Programs in a Collection
func (coll *Collection) ForEachProgram(fx func(string, Program)) {
	for k, v := range coll.programMap {
		fx(k, v)
	}
}

// GetMapByName get a Map by its symbolic name
func (coll *Collection) GetMapByName(key string) (Map, bool) {
	v, ok := coll.mapMap[key]
	return v, ok
}

// GetProgramByName get a Program by its symbolic name
func (coll *Collection) GetProgramByName(key string) (Program, bool) {
	v, ok := coll.programMap[key]
	return v, ok
}

// Pin persits a Collection beyond the lifetime of the process that created it
func (coll *Collection) Pin(dirName string, fileMode os.FileMode) error {
	err := mkdirIfNotExists(dirName, fileMode)
	if err != nil {
		return err
	}
	if len(coll.mapMap) > 0 {
		mapPath := path.Join(dirName, "maps")
		err = mkdirIfNotExists(mapPath, fileMode)
		if err != nil {
			return err
		}
		for k, v := range coll.mapMap {
			err := v.Pin(path.Join(mapPath, k))
			if err != nil {
				return err
			}
		}
	}
	if len(coll.programMap) > 0 {
		progPath := path.Join(dirName, "programs")
		err = mkdirIfNotExists(progPath, fileMode)
		if err != nil {
			return err
		}
		for k, v := range coll.programMap {
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
		mapMap:     make(map[string]Map),
		programMap: make(map[string]Program),
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
			bpfColl.mapMap[fi.Name()] = m
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
			bpfColl.programMap[fi.Name()] = p
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
	return NewCollectionFromObjectCode(f)
}

// NewCollectionFromObjectCode parses a raw object file buffer
func NewCollectionFromObjectCode(code io.ReaderAt) (*Collection, error) {
	programMap, mapMap, err := getSpecsFromELF(code)
	if err != nil {
		return nil, err
	}
	bpfColl := &Collection{
		mapMap:     make(map[string]Map),
		programMap: make(map[string]Program),
	}
	for k, v := range mapMap {
		bpfMap, err := NewMapFromSpec(v)
		if err != nil {
			return nil, err
		}
		bpfColl.mapMap[k] = bpfMap
		if v.instructionReplacements != nil {
			fd := int32(uint32(bpfMap))
			for _, ins := range v.instructionReplacements {
				ins.SrcRegister = 1
				ins.Constant = fd
			}
		}

	}
	for k, v := range programMap {
		bpfProg, err := NewProgramFromSpec(v)
		if err != nil {
			return nil, err
		}
		bpfColl.programMap[k] = bpfProg
	}
	return bpfColl, nil
}
