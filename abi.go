package ebpf

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/pkg/errors"
)

// CollectionABI describes the interface of an eBPF collection.
type CollectionABI struct {
	Maps     map[string]*MapABI
	Programs map[string]*ProgramABI
}

// CheckSpec verifies that all maps and programs mentioned
// in the ABI are present in the spec.
func (abi *CollectionABI) CheckSpec(cs *CollectionSpec) error {
	for name := range abi.Maps {
		if cs.Maps[name] == nil {
			return errors.Errorf("missing map %s", name)
		}
	}

	for name := range abi.Programs {
		if cs.Programs[name] == nil {
			return errors.Errorf("missing program %s", name)
		}
	}

	return nil
}

// Check verifies that all items in a collection conform to this ABI.
func (abi *CollectionABI) Check(coll *Collection) error {
	for name, mapABI := range abi.Maps {
		m := coll.Maps[name]
		if m == nil {
			return errors.Errorf("missing map %s", name)
		}
		if err := mapABI.Check(m); err != nil {
			return errors.Wrapf(err, "map %s", name)
		}
	}

	for name, progABI := range abi.Programs {
		p := coll.Programs[name]
		if p == nil {
			return errors.Errorf("missing program %s", name)
		}
		if err := progABI.Check(p); err != nil {
			return errors.Wrapf(err, "program %s", name)
		}
	}

	return nil
}

// MapABI describes a Map.
//
// Use it to assert that a Map matches what your code expects.
type MapABI struct {
	Type       MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	InnerMap   *MapABI
}

func newMapABIFromSpec(spec *MapSpec) *MapABI {
	var inner *MapABI
	if spec.InnerMap != nil {
		inner = newMapABIFromSpec(spec.InnerMap)
	}

	return &MapABI{
		spec.Type,
		spec.KeySize,
		spec.ValueSize,
		spec.MaxEntries,
		inner,
	}
}

func newMapABIFromFd(fd *bpfFD) (string, *MapABI, error) {
	info, err := bpfGetMapInfoByFD(fd)
	if err != nil {
		if errors.Cause(err) == syscall.EINVAL {
			abi, err := newMapABIFromProc(fd)
			return "", abi, err
		}
		return "", nil, err
	}

	mapType := MapType(info.mapType)
	if mapType == ArrayOfMaps || mapType == HashOfMaps {
		return "", nil, errors.New("can't get map info for nested maps")
	}

	name := convertCString(info.mapName[:])

	return name, &MapABI{
		mapType,
		info.keySize,
		info.valueSize,
		info.maxEntries,
		nil,
	}, nil
}

func newMapABIFromProc(fd *bpfFD) (*MapABI, error) {
	var abi MapABI
	err := scanFdInfo(fd, map[string]interface{}{
		"map_type":    &abi.Type,
		"key_size":    &abi.KeySize,
		"value_size":  &abi.ValueSize,
		"max_entries": &abi.MaxEntries,
	})
	if err != nil {
		return nil, err
	}

	if abi.Type == ArrayOfMaps || abi.Type == HashOfMaps {
		return nil, errors.New("can't get map info for nested maps")
	}

	return &abi, nil
}

// Check verifies that a Map conforms to the ABI.
//
// Members of ABI which have the zero value of their type are not checked.
func (abi *MapABI) Check(m *Map) error {
	return abi.check(&m.abi)
}

func (abi *MapABI) check(other *MapABI) error {
	if abi.Type != UnspecifiedMap && other.Type != abi.Type {
		return errors.Errorf("expected map type %s, have %s", abi.Type, other.Type)
	}
	if err := checkUint32("key size", abi.KeySize, other.KeySize); err != nil {
		return err
	}
	if err := checkUint32("value size", abi.ValueSize, other.ValueSize); err != nil {
		return err
	}
	if err := checkUint32("max entries", abi.MaxEntries, other.MaxEntries); err != nil {
		return err
	}

	if abi.InnerMap == nil {
		if abi.Type == ArrayOfMaps || abi.Type == HashOfMaps {
			return errors.New("missing inner map ABI")
		}

		return nil
	}

	if other.InnerMap == nil {
		return errors.New("missing inner map")
	}

	return errors.Wrap(abi.InnerMap.check(other.InnerMap), "inner map")
}

// ProgramABI describes a Program.
//
// Use it to assert that a Program matches what your code expects.
type ProgramABI struct {
	Type ProgramType
}

func newProgramABIFromSpec(spec *ProgramSpec) *ProgramABI {
	return &ProgramABI{
		spec.Type,
	}
}

func newProgramABIFromFd(fd *bpfFD) (string, *ProgramABI, error) {
	info, err := bpfGetProgInfoByFD(fd)
	if err != nil {
		if errors.Cause(err) == syscall.EINVAL {
			return newProgramABIFromProc(fd)
		}

		return "", nil, err
	}

	var name string
	if bpfName := convertCString(info.name[:]); bpfName != "" {
		name = bpfName
	} else {
		name = convertCString(info.tag[:])
	}

	return name, &ProgramABI{
		Type: ProgramType(info.progType),
	}, nil
}

func newProgramABIFromProc(fd *bpfFD) (string, *ProgramABI, error) {
	var (
		abi  ProgramABI
		name string
	)

	err := scanFdInfo(fd, map[string]interface{}{
		"prog_type": &abi.Type,
		"prog_tag":  &name,
	})
	if err != nil {
		return "", nil, err
	}

	return name, &abi, nil
}

func scanFdInfo(fd *bpfFD, fields map[string]interface{}) error {
	raw, err := fd.value()
	if err != nil {
		return err
	}

	fh, err := os.Open(fmt.Sprintf("/proc/self/fdinfo/%d", raw))
	if err != nil {
		return err
	}
	defer fh.Close()

	return errors.Wrap(scanFdInfoReader(fh, fields), fh.Name())
}

func scanFdInfoReader(r io.Reader, fields map[string]interface{}) error {
	var (
		scanner = bufio.NewScanner(r)
		scanned int
	)

	for scanner.Scan() {
		parts := bytes.SplitN(scanner.Bytes(), []byte("\t"), 2)
		if len(parts) != 2 {
			continue
		}

		name := bytes.TrimSuffix(parts[0], []byte(":"))
		field, ok := fields[string(name)]
		if !ok {
			continue
		}

		if n, err := fmt.Fscanln(bytes.NewReader(parts[1]), field); err != nil || n != 1 {
			return errors.Wrapf(err, "can't parse field %s", name)
		}

		scanned++
	}

	if err := scanner.Err(); err != nil {
		return err
	}

	if scanned != len(fields) {
		return errors.Errorf("parsed %d instead of %d fields", scanned, len(fields))
	}

	return nil
}

// Check verifies that a Program conforms to the ABI.
//
// Members which have the zero value of their type
// are not checked.
func (abi *ProgramABI) Check(prog *Program) error {
	if abi.Type != UnspecifiedProgram && prog.abi.Type != abi.Type {
		return errors.Errorf("expected program type %s, have %s", abi.Type, prog.abi.Type)
	}

	return nil
}

func checkUint32(name string, want, have uint32) error {
	if want != 0 && have != want {
		return errors.Errorf("expected %s to be %d, have %d", name, want, have)
	}
	return nil
}
