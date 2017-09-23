// Copyright 2017 Nathan Sweet. All rights reserved.
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
package ebpf

import (
	"io"
	"io/ioutil"
	"os"
	"path"
)

type BPFCollection struct {
	programMap map[string]BPFProgram
	mapMap     map[string]BPFMap
}

func (coll *BPFCollection) ForEachMap(fx func(string, BPFMap)) {
	for k, v := range coll.mapMap {
		fx(unReplaceForwardSlash(k), v)
	}
}

func (coll *BPFCollection) ForEachProgram(fx func(string, BPFProgram)) {
	for k, v := range coll.programMap {
		fx(unReplaceForwardSlash(k), v)
	}
}

func (coll *BPFCollection) GetMapByName(key string) (BPFMap, bool) {
	v, ok := coll.mapMap[replaceForwardSlash(key)]
	return v, ok
}

func (coll *BPFCollection) GetProgramByName(key string) (BPFProgram, bool) {
	v, ok := coll.programMap[replaceForwardSlash(key)]
	return v, ok
}

func (coll *BPFCollection) Pin(dirName string, fileMode os.FileMode) error {
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
			err := v.Pin(path.Join(mapPath, replaceForwardSlash(k)))
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
			err = v.Pin(path.Join(progPath, replaceForwardSlash(k)))
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

func LoadBPFCollection(dirName string) (*BPFCollection, error) {
	bpfColl := &BPFCollection{
		mapMap:     make(map[string]BPFMap),
		programMap: make(map[string]BPFProgram),
	}
	mapsDir := path.Join(dirName, "maps")
	files, err := ioutil.ReadDir(mapsDir)
	if err != nil && err != os.ErrNotExist {
		return nil, err
	}
	if len(files) > 0 {
		for _, fi := range files {
			m, err := LoadBPFMap(path.Join(mapsDir, fi.Name()))
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
			p, err := LoadBPFProgram(path.Join(programDir, fi.Name()))
			if err != nil {
				return nil, err
			}
			bpfColl.programMap[fi.Name()] = p
		}
	}
	return bpfColl, nil
}

func NewBPFCollectionFromFile(file string) (*BPFCollection, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return NewBPFCollectionFromObjectCode(f)
}

func NewBPFCollectionFromObjectCode(code io.ReaderAt) (*BPFCollection, error) {
	programMap, mapMap, err := getSpecsFromELF(code)
	if err != nil {
		return nil, err
	}
	bpfColl := &BPFCollection{
		mapMap:     make(map[string]BPFMap),
		programMap: make(map[string]BPFProgram),
	}
	for k, v := range mapMap {
		bpfMap, err := NewBPFMapFromSpec(v)
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
		bpfProg, err := NewBPFProgramFromSpec(v)
		if err != nil {
			return nil, err
		}
		bpfColl.programMap[k] = bpfProg
	}
	return bpfColl, nil
}
