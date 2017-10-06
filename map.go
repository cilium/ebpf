package ebpf

import (
	"encoding"
	"fmt"
	"syscall"
	"unsafe"
)

// MapSpec is an interface type that cna initialize a new Map
type MapSpec interface {
	MapType() MapType
	KeySize() uint32
	ValueSize() uint32
	MaxEntries() uint32
	Flags() uint32
}

// Map represents a Map file descriptor
type Map int

// NewMap creates a new Map
func NewMap(mapType MapType, keySize, valueSize, maxEntries, flags uint32) (Map, error) {
	fd, e := bpfCall(_MapCreate, unsafe.Pointer(&mapCreateAttr{mapType, keySize, valueSize, maxEntries, flags}), 20)
	err := bpfErrNo(e)
	if err != nil {
		return Map(-1), fmt.Errorf("map create: %s", err.Error())
	}
	return Map(fd), nil
}

// NewMapFromSpec creates a new Map from a MapSpec
func NewMapFromSpec(spec MapSpec) (Map, error) {
	return NewMap(spec.MapType(), spec.KeySize(), spec.ValueSize(), spec.MaxEntries(), spec.Flags())
}

// Get gets a value from a Map
func (m Map) Get(key encoding.BinaryMarshaler, value encoding.BinaryUnmarshaler, valueSize int) (bool, error) {
	v := make([]byte, valueSize)
	ok, err := m.GetRaw(key, &v)
	if err != nil || !ok {
		return ok, err
	}
	err = value.UnmarshalBinary(v)
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetRaw gets a value from Map populating a raw byte array
func (m Map) GetRaw(key encoding.BinaryMarshaler, value *[]byte) (bool, error) {
	keyValue, err := key.MarshalBinary()
	if err != nil {
		return false, err
	}
	_, e := bpfCall(_MapLookupElem,
		unsafe.Pointer(&mapOpAttr{
			mapFd: uint32(m),
			key:   uint64(uintptr(unsafe.Pointer(&keyValue[0]))),
			value: uint64(uintptr(unsafe.Pointer(&(*value)[0]))),
		}), 32)
	if e != 0 {
		if e == syscall.ENOENT {
			return false, nil
		}
		return false, bpfErrNo(e)
	}
	return true, nil
}

// Create creates a new value in a map, failing if the key exists already
func (m Map) Create(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) (bool, error) {
	return m.put(key, value, _NoExist)
}

// Put replaces or creates a value in map
func (m Map) Put(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) error {
	_, err := m.put(key, value, _Any)
	return err
}

// Replace replaces a value in a map, failing if the value did not exist
func (m Map) Replace(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) (bool, error) {
	return m.put(key, value, _Exist)
}

// Delete removes a value, failing if the value does not exist
func (m Map) Delete(key encoding.BinaryMarshaler) (bool, error) {
	keyValue, err := key.MarshalBinary()
	if err != nil {
		return false, err
	}
	_, e := bpfCall(_MapDeleteElem,
		unsafe.Pointer(&mapOpAttr{
			mapFd: uint32(m),
			key:   uint64(uintptr(unsafe.Pointer(&keyValue[0]))),
		}), 32)
	if e == 0 {
		return true, nil
	}
	if e == syscall.ENOENT {
		return false, nil
	}
	return false, bpfErrNo(e)
}

// GetNextKey helps to iterate over a map getting the next key after a known key
func (m Map) GetNextKey(key encoding.BinaryMarshaler, nextKey encoding.BinaryUnmarshaler, keySize int) (bool, error) {
	v := make([]byte, keySize)
	ok, err := m.GetNextKeyRaw(key, &v)
	if err != nil || !ok {
		return ok, err
	}
	err = nextKey.UnmarshalBinary(v)
	if err != nil {
		return false, err
	}
	return true, nil
}

// GetNextKeyRaw helps to iterate over a map getting the next key after a known key by a raw byte array
func (m Map) GetNextKeyRaw(key encoding.BinaryMarshaler, nextKey *[]byte) (bool, error) {
	keyValue, err := key.MarshalBinary()
	if err != nil {
		return false, err
	}
	_, e := bpfCall(_MapGetNextKey,
		unsafe.Pointer(&mapOpAttr{
			mapFd: uint32(m),
			key:   uint64(uintptr(unsafe.Pointer(&keyValue[0]))),
			value: uint64(uintptr(unsafe.Pointer(&(*nextKey)[0]))),
		}), 32)
	if e != 0 {
		if e == syscall.ENOENT {
			return false, nil
		}
		return false, bpfErrNo(e)
	}
	return true, nil
}

// Close removes a Map
func (m Map) Close() error {
	return syscall.Close(m.GetFd())
}

// GetFd gets the raw fd value of Map
func (m Map) GetFd() int {
	return int(m)
}

// Pin persists the map past the lifetime of the process that created it
func (m Map) Pin(fileName string) error {
	return pinObject(fileName, uint32(m))
}

// LoadMap load a Map from
func LoadMap(fileName string) (Map, error) {
	ptr, err := getObject(fileName)
	return Map(ptr), err
}

func (m Map) put(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler, putType uint64) (bool, error) {
	keyValue, err := key.MarshalBinary()
	if err != nil {
		return false, err
	}
	v, err := value.MarshalBinary()
	if err != nil {
		return false, err
	}
	_, e := bpfCall(_MapUpdateElem,
		unsafe.Pointer(&mapOpAttr{
			mapFd: uint32(m),
			key:   uint64(uintptr(unsafe.Pointer(&keyValue[0]))),
			value: uint64(uintptr(unsafe.Pointer(&v[0]))),
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
