package ebpf

import (
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
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

// Map represents a Map file descriptor.
//
// Methods which take interface{} arguments by default encode
// them using binary.Read/Write in the machine's native endianness.
//
// Implement Marshaler on the arguments if you need custom encoding.
type Map struct {
	fd  uint32
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
		return createMap(spec, 0)
	}

	if spec.InnerMap == nil {
		return nil, errors.Errorf("%s requires InnerMap", spec.Type)
	}

	template, err := createMap(spec.InnerMap, 0)
	if err != nil {
		return nil, err
	}
	defer template.Close()

	return createMap(spec, template.fd)
}

func createMap(spec *MapSpec, inner uint32) (*Map, error) {
	cpy := *spec
	switch spec.Type {
	case ArrayOfMaps:
		fallthrough
	case HashOfMaps:
		if spec.ValueSize != 0 {
			return nil, errors.Errorf("ValueSize must be zero for map of map")
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
		innerMapFd: inner,
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

	return newMap(uint32(fd), newMapABIFromSpec(&cpy))
}

func newMap(fd uint32, abi *MapABI) (*Map, error) {
	m := &Map{
		uint32(fd),
		*abi,
		int(abi.ValueSize),
	}
	runtime.SetFinalizer(m, (*Map).Close)

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

// Get gets a value from a Map
func (m *Map) Get(key, valueOut interface{}) (bool, error) {
	valueBytes, err := m.GetBytes(key)
	if err != nil {
		return false, err
	}
	if valueBytes == nil {
		return false, nil
	}

	if m.abi.Type.hasPerCPUValue() {
		return true, unmarshalPerCPUValue(valueOut, int(m.abi.ValueSize), valueBytes)
	}

	return true, unmarshalBytes(valueOut, valueBytes)
}

// GetBytes gets a value from Map
func (m *Map) GetBytes(key interface{}) ([]byte, error) {
	keyBytes, err := marshalBytes(key, int(m.abi.KeySize))
	if err != nil {
		return nil, err
	}
	valueBytes := make([]byte, m.fullValueSize)
	attr := bpfMapOpAttr{
		mapFd: m.fd,
		key:   newPtr(unsafe.Pointer(&keyBytes[0])),
		value: newPtr(unsafe.Pointer(&valueBytes[0])),
	}
	_, err = bpfCall(_MapLookupElem, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if errors.Cause(err) == syscall.ENOENT {
		return nil, nil
	}
	return valueBytes, err
}

// Create creates a new value in a map, failing if the key exists already
func (m *Map) Create(key, value interface{}) error {
	return m.put(key, value, _NoExist)
}

// Put replaces or creates a value in map
func (m *Map) Put(key, value interface{}) error {
	return m.put(key, value, _Any)
}

// Replace replaces a value in a map, failing if the value did not exist
func (m *Map) Replace(key, value interface{}) error {
	return m.put(key, value, _Exist)
}

// Delete removes a value.
//
// Use DeleteStrict if you desire an error if key does not exist.
func (m *Map) Delete(key interface{}) error {
	err := m.DeleteStrict(key)
	if err == syscall.ENOENT {
		return nil
	}
	return err
}

// DeleteStrict removes a key and returns an error if the
// key doesn't exist.
func (m *Map) DeleteStrict(key interface{}) error {
	keyBytes, err := marshalBytes(key, int(m.abi.KeySize))
	if err != nil {
		return err
	}
	attr := bpfMapOpAttr{
		mapFd: m.fd,
		key:   newPtr(unsafe.Pointer(&keyBytes[0])),
	}
	_, err = bpfCall(_MapDeleteElem, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return err
}

// NextKey finds the key following an initial key.
//
// See NextKeyBytes for details.
func (m *Map) NextKey(key, nextKeyOut interface{}) (bool, error) {
	nextKeyBytes, err := m.NextKeyBytes(key)
	if err != nil {
		return false, err
	}
	if nextKeyBytes == nil {
		return false, nil
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
	var keyPtr syscallPtr
	if key != nil {
		keyBytes, err := marshalBytes(key, int(m.abi.KeySize))
		if err != nil {
			return nil, err
		}
		keyPtr = newPtr(unsafe.Pointer(&keyBytes[0]))
	}

	nextKey := make([]byte, m.abi.KeySize)
	attr := bpfMapOpAttr{
		mapFd: m.fd,
		key:   keyPtr,
		value: newPtr(unsafe.Pointer(&nextKey[0])),
	}
	_, err := bpfCall(_MapGetNextKey, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	if errors.Cause(err) == syscall.ENOENT {
		return nil, nil
	}
	return nextKey, err
}

// Iterate traverses a map.
//
// It's not possible to guarantee that all keys in a map will be
// returned if there are concurrent modifications to the map. If a
// map is modified too heavily iteration may abort.
func (m *Map) Iterate() *MapIterator {
	return &MapIterator{
		target: m,
	}
}

// Close removes a Map
func (m *Map) Close() error {
	runtime.SetFinalizer(m, nil)
	return syscall.Close(int(m.fd))
}

// FD gets the raw fd value of Map
func (m *Map) FD() int {
	return int(m.fd)
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

func (m *Map) put(key, value interface{}, putType uint64) error {
	keyBytes, err := marshalBytes(key, int(m.abi.KeySize))
	if err != nil {
		return err
	}

	var valueBytes []byte
	if m.abi.Type.hasPerCPUValue() {
		valueBytes, err = marshalPerCPUValue(value, int(m.abi.ValueSize))
	} else {
		valueBytes, err = marshalBytes(value, int(m.abi.ValueSize))
	}
	if err != nil {
		return err
	}

	attr := bpfMapOpAttr{
		mapFd: m.fd,
		key:   newPtr(unsafe.Pointer(&keyBytes[0])),
		value: newPtr(unsafe.Pointer(&valueBytes[0])),
		flags: putType,
	}
	_, err = bpfCall(_MapUpdateElem, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return err
}

// UnmarshalBinary implements BinaryUnmarshaler.
func (m *Map) UnmarshalBinary(buf []byte) error {
	if m.fd != 0 {
		return errors.New("ebpf: can't unmarshal into existing map")
	}
	if len(buf) != 4 {
		return errors.New("ebpf: map id requires uint32")
	}
	// Looking up an entry in a nested map or prog array returns an id,
	// not an fd.
	id := nativeEndian.Uint32(buf)
	fd, err := bpfGetMapFDByID(id)
	if err != nil {
		return err
	}
	abi, err := newMapABIFromFd(fd)
	if err != nil {
		return err
	}

	nm, err := newMap(fd, abi)
	if err != nil {
		return err
	}

	*m = *nm
	return nil
}

// MarshalBinary implements BinaryMarshaler.
func (m *Map) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 4)
	nativeEndian.PutUint32(buf, m.fd)
	return buf, nil
}

// MapIterator iterates a Map.
//
// See Map.Iterate.
type MapIterator struct {
	target *Map
	prev   interface{}
	done   bool
	err    error
}

// Next decodes the next key and value.
//
// Returns false if there are no more entries.
func (mi *MapIterator) Next(keyOut, valueOut interface{}) bool {
	if mi.err != nil || mi.done {
		return false
	}

	var nextBytes []byte
	for i := 0; i < 3; i++ {
		nextBytes, mi.err = mi.target.NextKeyBytes(mi.prev)
		if mi.err != nil {
			return false
		}

		if nextBytes == nil {
			mi.done = true
			return false
		}

		var ok bool
		ok, mi.err = mi.target.Get(nextBytes, valueOut)
		if mi.err != nil {
			return false
		}

		if ok {
			break
		}

		// The next key was deleted before we could retrieve
		// it's value. As of Linux 4.16 there is no safe API which
		// prevents this race.
		nextBytes = nil
	}

	if nextBytes == nil {
		// We still hit the race condition even though we retried.
		mi.err = errors.New("ebpf: can't retrieve next entry, map mutated too quickly")
		return false
	}

	mi.err = unmarshalBytes(keyOut, nextBytes)
	if mi.err != nil {
		return false
	}

	// The user can get access to nextBytes since marshalBytes
	// does not copy when unmarshaling into a []byte.
	// Make a copy to prevent accidental corruption of
	// iterator state.
	prevBytes := make([]byte, len(nextBytes))
	copy(prevBytes, nextBytes)
	mi.prev = prevBytes
	return true
}

// Err returns any encountered error.
//
// The method must be called after Next returns nil.
func (mi *MapIterator) Err() error {
	return mi.err
}
