package ebpf

import (
	"fmt"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// MapSpec defines a Map.
type MapSpec struct {
	// Name is passed to the kernel as a debug aid. Must only contain
	// alpha numeric and '_' characters.
	Name       string
	Type       MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
	// InnerMap is used as a template for ArrayOfMaps and HashOfMaps
	InnerMap *MapSpec
}

func (ms *MapSpec) String() string {
	return fmt.Sprintf("%s(keySize=%d, valueSize=%d, maxEntries=%d, flags=%d)", ms.Type, ms.KeySize, ms.ValueSize, ms.MaxEntries, ms.Flags)
}

// Copy returns a copy of the spec.
func (ms *MapSpec) Copy() *MapSpec {
	if ms == nil {
		return nil
	}

	cpy := *ms
	cpy.InnerMap = ms.InnerMap.Copy()
	return &cpy
}

// Map represents a Map file descriptor.
//
// It is not safe to close a map which is used by other goroutines.
//
// Methods which take interface{} arguments by default encode
// them using binary.Read/Write in the machine's native endianness.
//
// Implement Marshaler on the arguments if you need custom encoding.
type Map struct {
	fd  *bpfFD
	abi MapABI
	// Per CPU maps return values larger than the size in the spec
	fullValueSize int
}

// NewMap creates a new Map.
//
// Creating a map for the first time will perform feature detection
// by creating small, temporary maps.
func NewMap(spec *MapSpec) (*Map, error) {
	if spec.Type != ArrayOfMaps && spec.Type != HashOfMaps {
		return createMap(spec, nil)
	}

	if spec.InnerMap == nil {
		return nil, errors.Errorf("%s requires InnerMap", spec.Type)
	}

	template, err := createMap(spec.InnerMap, nil)
	if err != nil {
		return nil, err
	}
	defer template.Close()

	return createMap(spec, template.fd)
}

func createMap(spec *MapSpec, inner *bpfFD) (*Map, error) {
	cpy := *spec
	switch spec.Type {
	case ArrayOfMaps:
		fallthrough
	case HashOfMaps:
		if spec.ValueSize != 0 && spec.ValueSize != 4 {
			return nil, errors.Errorf("ValueSize must be zero or four for map of map")
		}
		cpy.ValueSize = 4

	case PerfEventArray:
		if spec.KeySize != 0 {
			return nil, errors.Errorf("KeySize must be zero for perf event array")
		}
		if spec.ValueSize != 0 {
			return nil, errors.Errorf("ValueSize must be zero for perf event array")
		}
		if spec.MaxEntries != 0 {
			return nil, errors.Errorf("MaxEntries must be zero for perf event array")
		}

		n, err := possibleCPUs()
		if err != nil {
			return nil, errors.Wrap(err, "perf event array")
		}
		cpy.KeySize = 4
		cpy.ValueSize = 4
		cpy.MaxEntries = uint32(n)
	}

	attr := bpfMapCreateAttr{
		mapType:    cpy.Type,
		keySize:    cpy.KeySize,
		valueSize:  cpy.ValueSize,
		maxEntries: cpy.MaxEntries,
		flags:      cpy.Flags,
	}

	if inner != nil {
		var err error
		attr.innerMapFd, err = inner.value()
		if err != nil {
			return nil, errors.Wrap(err, "map create")
		}
	}

	name, err := newBPFObjName(spec.Name)
	if err != nil {
		return nil, errors.Wrap(err, "map create")
	}

	if haveObjName.Result() {
		attr.mapName = name
	}

	fd, err := bpfMapCreate(&attr)
	if err != nil {
		return nil, errors.Wrap(err, "map create")
	}

	return newMap(fd, newMapABIFromSpec(&cpy))
}

func newMap(fd *bpfFD, abi *MapABI) (*Map, error) {
	m := &Map{
		fd,
		*abi,
		int(abi.ValueSize),
	}

	if !abi.Type.hasPerCPUValue() {
		return m, nil
	}

	possibleCPUs, err := possibleCPUs()
	if err != nil {
		return nil, err
	}

	m.fullValueSize = align(int(abi.ValueSize), 8) * possibleCPUs
	return m, nil
}

func (m *Map) String() string {
	return fmt.Sprintf("%s#%d", m.abi.Type, m.fd)
}

// ABI gets the ABI of the Map
func (m *Map) ABI() MapABI {
	return m.abi
}

// Get retrieves a value from a Map.
//
// Calls Close() on valueOut if it is of type **Map or **Program,
// and *valueOut is not nil.
func (m *Map) Get(key, valueOut interface{}) (bool, error) {
	valuePtr, valueBytes := makeBuffer(valueOut, m.fullValueSize)

	err := m.lookup(key, valuePtr)
	if errors.Cause(err) == unix.ENOENT {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	if valueBytes == nil {
		return true, nil
	}

	if m.abi.Type.hasPerCPUValue() {
		return true, unmarshalPerCPUValue(valueOut, int(m.abi.ValueSize), valueBytes)
	}

	switch value := valueOut.(type) {
	case **Map:
		m, err := unmarshalMap(valueBytes)
		if err != nil {
			return true, err
		}

		(*value).Close()
		*value = m
		return true, nil
	case *Map:
		return true, errors.Errorf("can't unmarshal into %T, need %T", value, (**Map)(nil))
	case Map:
		return true, errors.Errorf("can't unmarshal into %T, need %T", value, (**Map)(nil))

	case **Program:
		p, err := unmarshalProgram(valueBytes)
		if err != nil {
			return true, err
		}

		(*value).Close()
		*value = p
		return true, nil
	case *Program:
		return true, errors.Errorf("can't unmarshal into %T, need %T", value, (**Program)(nil))
	case Program:
		return true, errors.Errorf("can't unmarshal into %T, need %T", value, (**Program)(nil))

	default:
		return true, unmarshalBytes(valueOut, valueBytes)
	}
}

// GetBytes gets a value from Map
func (m *Map) GetBytes(key interface{}) ([]byte, error) {
	valueBytes := make([]byte, m.fullValueSize)
	valuePtr := newPtr(unsafe.Pointer(&valueBytes[0]))

	err := m.lookup(key, valuePtr)
	if errors.Cause(err) == unix.ENOENT {
		return nil, nil
	}

	return valueBytes, err
}

func (m *Map) lookup(key interface{}, valueOut syscallPtr) error {
	keyPtr, err := marshalPtr(key, int(m.abi.KeySize))
	if err != nil {
		return errors.Wrap(err, "key")
	}

	return bpfMapLookupElem(m.fd, keyPtr, valueOut)
}

// Create creates a new value in a map, failing if the key exists already
func (m *Map) Create(key, value interface{}) error {
	return m.update(key, value, _NoExist)
}

// Put replaces or creates a value in map
func (m *Map) Put(key, value interface{}) error {
	return m.update(key, value, _Any)
}

// Replace replaces a value in a map, failing if the value did not exist
func (m *Map) Replace(key, value interface{}) error {
	return m.update(key, value, _Exist)
}

// Delete removes a value.
//
// Use DeleteStrict if you desire an error if key does not exist.
func (m *Map) Delete(key interface{}) error {
	err := m.DeleteStrict(key)
	if err == unix.ENOENT {
		return nil
	}
	return err
}

// DeleteStrict removes a key and returns an error if the
// key doesn't exist.
func (m *Map) DeleteStrict(key interface{}) error {
	keyPtr, err := marshalPtr(key, int(m.abi.KeySize))
	if err != nil {
		return err
	}

	return bpfMapDeleteElem(m.fd, keyPtr)
}

// NextKey finds the key following an initial key.
//
// See NextKeyBytes for details.
func (m *Map) NextKey(key, nextKeyOut interface{}) (bool, error) {
	nextKeyPtr, nextKeyBytes := makeBuffer(nextKeyOut, int(m.abi.KeySize))

	err := m.nextKey(key, nextKeyPtr)
	if errors.Cause(err) == unix.ENOENT {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	if nextKeyBytes == nil {
		return true, nil
	}

	err = unmarshalBytes(nextKeyOut, nextKeyBytes)
	if err != nil {
		return false, err
	}
	return true, nil
}

// NextKeyBytes returns the key following an initial key as a byte slice.
//
// Passing nil will return the first key.
//
// Use Iterate if you want to traverse all entries in the map.
func (m *Map) NextKeyBytes(key interface{}) ([]byte, error) {
	nextKey := make([]byte, m.abi.KeySize)
	nextKeyPtr := newPtr(unsafe.Pointer(&nextKey[0]))

	err := m.nextKey(key, nextKeyPtr)
	if errors.Cause(err) == unix.ENOENT {
		return nil, nil
	}

	return nextKey, err
}

func (m *Map) nextKey(key interface{}, nextKeyOut syscallPtr) error {
	var (
		keyPtr syscallPtr
		err    error
	)

	if key != nil {
		keyPtr, err = marshalPtr(key, int(m.abi.KeySize))
		if err != nil {
			return err
		}
	}

	return bpfMapGetNextKey(m.fd, keyPtr, nextKeyOut)
}

// Iterate traverses a map.
//
// It's safe to create multiple iterators at the same time.
//
// It's not possible to guarantee that all keys in a map will be
// returned if there are concurrent modifications to the map.
func (m *Map) Iterate() *MapIterator {
	return newMapIterator(m)
}

// Close removes a Map
func (m *Map) Close() error {
	if m == nil {
		// This makes it easier to clean up when iterating maps
		// of maps / programs.
		return nil
	}

	return m.fd.close()
}

// FD gets the file descriptor of the Map.
//
// Calling this function is invalid after Close has been called.
func (m *Map) FD() int {
	fd, err := m.fd.value()
	if err != nil {
		// Best effort: -1 is the number most likely to be an
		// invalid file descriptor.
		return -1
	}

	return int(fd)
}

// Clone creates a duplicate of the Map.
//
// Closing the duplicate does not affect the original, and vice versa.
// Changes made to the map are reflected by both instances however.
//
// Cloning a nil Map returns nil.
func (m *Map) Clone() (*Map, error) {
	if m == nil {
		return nil, nil
	}

	dup, err := m.fd.dup()
	if err != nil {
		return nil, errors.Wrap(err, "can't clone map")
	}

	return newMap(dup, &m.abi)
}

// Pin persists the map past the lifetime of the process that created it.
//
// This requires bpffs to be mounted above fileName. See http://cilium.readthedocs.io/en/doc-1.0/kubernetes/install/#mounting-the-bpf-fs-optional
func (m *Map) Pin(fileName string) error {
	return bpfPinObject(fileName, m.fd)
}

// LoadPinnedMap load a Map from a BPF file.
//
// Requires at least Linux 4.13, and is not compatible with
// nested maps. Use LoadPinnedMapExplicit in these situations.
func LoadPinnedMap(fileName string) (*Map, error) {
	fd, err := bpfGetObject(fileName)
	if err != nil {
		return nil, err
	}
	abi, err := newMapABIFromFd(fd)
	if err != nil {
		_ = fd.close()
		return nil, err
	}
	return newMap(fd, abi)
}

// LoadPinnedMapExplicit loads a map with explicit parameters.
func LoadPinnedMapExplicit(fileName string, abi *MapABI) (*Map, error) {
	fd, err := bpfGetObject(fileName)
	if err != nil {
		return nil, err
	}
	return newMap(fd, abi)
}

func (m *Map) update(key, value interface{}, putType uint64) error {
	keyPtr, err := marshalPtr(key, int(m.abi.KeySize))
	if err != nil {
		return err
	}

	var valuePtr syscallPtr
	if m.abi.Type.hasPerCPUValue() {
		valuePtr, err = marshalPerCPUValue(value, int(m.abi.ValueSize))
	} else {
		valuePtr, err = marshalPtr(value, int(m.abi.ValueSize))
	}
	if err != nil {
		return err
	}

	return bpfMapUpdateElem(m.fd, keyPtr, valuePtr, putType)
}

func unmarshalMap(buf []byte) (*Map, error) {
	if len(buf) != 4 {
		return nil, errors.New("map id requires 4 byte value")
	}

	// Looking up an entry in a nested map or prog array returns an id,
	// not an fd.
	id := nativeEndian.Uint32(buf)
	fd, err := bpfGetMapFDByID(id)
	if err != nil {
		return nil, err
	}

	abi, err := newMapABIFromFd(fd)
	if err != nil {
		_ = fd.close()
		return nil, err
	}

	return newMap(fd, abi)
}

// MarshalBinary implements BinaryMarshaler.
func (m *Map) MarshalBinary() ([]byte, error) {
	fd, err := m.fd.value()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 4)
	nativeEndian.PutUint32(buf, fd)
	return buf, nil
}

// MapIterator iterates a Map.
//
// See Map.Iterate.
type MapIterator struct {
	target    *Map
	prevKey   interface{}
	prevBytes []byte
	done      bool
	err       error
}

func newMapIterator(target *Map) *MapIterator {
	return &MapIterator{
		target:    target,
		prevBytes: make([]byte, int(target.abi.KeySize)),
	}
}

// Next decodes the next key and value.
//
// Returns false if there are no more entries.
//
// See Map.Get for further caveats around valueOut.
func (mi *MapIterator) Next(keyOut, valueOut interface{}) bool {
	if mi.err != nil || mi.done {
		return false
	}

	for {
		var nextBytes []byte
		nextBytes, mi.err = mi.target.NextKeyBytes(mi.prevKey)
		if mi.err != nil {
			return false
		}

		if nextBytes == nil {
			mi.done = true
			return false
		}

		// The user can get access to nextBytes since unmarshalBytes
		// does not copy when unmarshaling into a []byte.
		// Make a copy to prevent accidental corruption of
		// iterator state.
		copy(mi.prevBytes, nextBytes)
		mi.prevKey = mi.prevBytes

		var ok bool
		ok, mi.err = mi.target.Get(nextBytes, valueOut)
		if mi.err != nil {
			return false
		}

		if !ok {
			// Even though the key should be valid, we couldn't look up
			// its value. If we're iterating a hash map this is probably
			// because a concurrent delete removed the value before we
			// could get it. If we're iterating one of the fd maps like
			// ProgramArray it means that a given slot doesn't have
			// a valid fd associated.
			// In either case there isn't much we can do, so just
			// continue to the next key.
			continue
		}

		mi.err = unmarshalBytes(keyOut, nextBytes)
		return mi.err == nil
	}
}

// Err returns any encountered error.
//
// The method must be called after Next returns nil.
func (mi *MapIterator) Err() error {
	return mi.err
}
