package ebpf

import (
	"encoding"
	"fmt"
	"syscall"
	"unsafe"
)

// MapSpec is an interface type that cna initialize a new Map
type MapSpec struct {
	Type       MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

func (ms *MapSpec) String() string {
	return fmt.Sprintf("%s(keySize=%d, valueSize=%d, maxEntries=%d, flags=%d)", ms.Type, ms.KeySize, ms.ValueSize, ms.MaxEntries, ms.Flags)
}

// Map represents a Map file descriptor
type Map struct {
	fd   uint32
	meta MapSpec
}

// NewMap creates a new Map
func NewMap(spec *MapSpec) (*Map, error) {
	attr := mapCreateAttr{
		spec.Type,
		spec.KeySize,
		spec.ValueSize,
		spec.MaxEntries,
		spec.Flags,
	}
	fd, e := bpfCall(_MapCreate, unsafe.Pointer(&attr), int(unsafe.Sizeof(attr)))
	err := bpfErrNo(e)
	if err != nil {
		return nil, fmt.Errorf("map create: %s", err.Error())
	}
	return &Map{
		uint32(fd),
		*spec,
	}, nil
}

func (m *Map) String() string {
	return fmt.Sprintf("%s#%d", m.meta.Type, m.fd)
}

// Get gets a value from a Map
func (m *Map) Get(key encoding.BinaryMarshaler, value encoding.BinaryUnmarshaler) (bool, error) {
	valueBytes, err := m.GetRaw(key)
	if err != nil {
		return false, err
	}
	if valueBytes == nil {
		return false, nil
	}
	err = value.UnmarshalBinary(valueBytes)
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetRaw gets a value from Map
func (m *Map) GetRaw(key encoding.BinaryMarshaler) ([]byte, error) {
	keyBytes, err := m.marshal(key, m.meta.KeySize)
	if err != nil {
		return nil, err
	}
	valueBytes := make([]byte, int(m.meta.ValueSize))
	attr := mapOpAttr{
		mapFd: uint32(m.fd),
		key:   newPtr(unsafe.Pointer(&keyBytes[0])),
		value: newPtr(unsafe.Pointer(&valueBytes[0])),
	}
	_, errNo := bpfCall(_MapLookupElem, unsafe.Pointer(&attr), int(unsafe.Sizeof(attr)))
	if errNo == syscall.ENOENT {
		return nil, nil
	} else if errNo != 0 {
		return nil, bpfErrNo(errNo)
	}
	return valueBytes, nil
}

// Create creates a new value in a map, failing if the key exists already
func (m *Map) Create(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) (bool, error) {
	return m.put(key, value, _NoExist)
}

// Put replaces or creates a value in map
func (m *Map) Put(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) error {
	_, err := m.put(key, value, _Any)
	return err
}

// Replace replaces a value in a map, failing if the value did not exist
func (m *Map) Replace(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) (bool, error) {
	return m.put(key, value, _Exist)
}

// Delete removes a value, failing if the value does not exist
func (m *Map) Delete(key encoding.BinaryMarshaler) (bool, error) {
	keyBytes, err := m.marshal(key, m.meta.KeySize)
	if err != nil {
		return false, err
	}
	attr := mapOpAttr{
		mapFd: m.fd,
		key:   newPtr(unsafe.Pointer(&keyBytes[0])),
	}
	_, e := bpfCall(_MapDeleteElem, unsafe.Pointer(&attr), int(unsafe.Sizeof(attr)))
	if e == 0 {
		return true, nil
	}
	if e == syscall.ENOENT {
		return false, nil
	}
	return false, bpfErrNo(e)
}

// GetNextKey helps to iterate over a map getting the next key after a known key
func (m *Map) GetNextKey(key encoding.BinaryMarshaler, nextKey encoding.BinaryUnmarshaler) (bool, error) {
	nextKeyBytes, err := m.GetNextKeyRaw(key)
	if err != nil {
		return false, err
	}
	if nextKeyBytes == nil {
		return false, nil
	}
	err = nextKey.UnmarshalBinary(nextKeyBytes)
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetNextKeyRaw helps to iterate over a map getting the next key after a known key by a raw byte array
func (m *Map) GetNextKeyRaw(key encoding.BinaryMarshaler) ([]byte, error) {
	keyBytes, err := m.marshal(key, m.meta.KeySize)
	if err != nil {
		return nil, err
	}
	nextKeyBytes := make([]byte, m.meta.KeySize)
	attr := mapOpAttr{
		mapFd: m.fd,
		key:   newPtr(unsafe.Pointer(&keyBytes[0])),
		value: newPtr(unsafe.Pointer(&nextKeyBytes[0])),
	}
	_, e := bpfCall(_MapGetNextKey, unsafe.Pointer(&attr), int(unsafe.Sizeof(attr)))
	if e != 0 {
		if e == syscall.ENOENT {
			return nil, nil
		}
		return nil, bpfErrNo(e)
	}
	return nextKeyBytes, nil
}

// Close removes a Map
func (m *Map) Close() error {
	return syscall.Close(int(m.fd))
}

// FD gets the raw fd value of Map
func (m *Map) FD() int {
	return int(m.fd)
}

// Pin persists the map past the lifetime of the process that created it
func (m *Map) Pin(fileName string) error {
	return pinObject(fileName, m.fd)
}

// LoadMap load a Map from a BPF file.
//
// Requires at least Linux 4.13, use LoadMapExplicit on
// earlier versions.
func LoadMap(fileName string) (*Map, error) {
	fd, err := getObject(fileName)
	if err != nil {
		return nil, err
	}
	var info mapInfo
	err = getObjectInfoByFD(uint32(fd), unsafe.Pointer(&info), unsafe.Sizeof(info))
	if err != nil {
		return nil, fmt.Errorf("ebpf: can't retrieve map info: %s", err.Error())
	}
	return &Map{
		uint32(fd),
		MapSpec{
			MapType(info.mapType),
			info.keySize,
			info.valueSize,
			info.maxEntries,
			info.flags,
		},
	}, nil
}

// LoadMapExplicit loads a map with explicit parameters.
func LoadMapExplicit(fileName string, spec *MapSpec) (*Map, error) {
	fd, err := getObject(fileName)
	if err != nil {
		return nil, err
	}
	return &Map{
		uint32(fd),
		*spec,
	}, nil
}

func (m *Map) put(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler, putType uint64) (bool, error) {
	keyBytes, err := m.marshal(key, m.meta.KeySize)
	if err != nil {
		return false, err
	}
	valueBytes, err := m.marshal(value, m.meta.ValueSize)
	if err != nil {
		return false, err
	}
	_, e := bpfCall(_MapUpdateElem,
		unsafe.Pointer(&mapOpAttr{
			mapFd: m.fd,
			key:   newPtr(unsafe.Pointer(&keyBytes[0])),
			value: newPtr(unsafe.Pointer(&valueBytes[0])),
			flags: putType,
		}), 32)
	if e != 0 {
		switch putType {
		case _NoExist:
			if e == syscall.EEXIST {
				return false, nil
			}
		case _Exist:
			if e == syscall.ENOENT {
				return false, nil
			}
		}
		return false, bpfErrNo(e)
	}
	return true, nil
}

func (m *Map) marshal(value encoding.BinaryMarshaler, length uint32) ([]byte, error) {
	bytes, err := value.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if l := int(length); len(bytes) != l {
		return nil, fmt.Errorf("%T must marshal to %d bytes, not %d", value, length, l)
	}
	return bytes, nil
}
