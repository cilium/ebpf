// Copyright 2017 Nathan Sweet. All rights reserved.
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
package ebpf

import (
	"encoding"
	"encoding/base64"
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

const (
	_key   = "key"
	_value = "value"
)

type BPFMap struct {
	mapType    MapType
	fd         int
	keySize    uint32
	valueSize  uint32
	maxEntries uint32
	flags      uint32

	keys     map[string]struct{}
	keysLock sync.RWMutex
}

func NewBPFMap(mapType MapType, keySize, valueSize, maxEntries, flags uint32) (*BPFMap, error) {
	fd, e := bpfCall(_BPF_MAP_CREATE, unsafe.Pointer(&mapCreateAttr{mapType, keySize, valueSize, maxEntries, flags}), 20)
	err := errnoErr(e)
	if err != nil {
		return nil, fmt.Errorf("map create: %s", err.Error())
	}
	return &BPFMap{
		mapType:    mapType,
		fd:         int(fd),
		keySize:    keySize,
		valueSize:  valueSize,
		maxEntries: maxEntries,
		flags:      flags,
		keys:       make(map[string]struct{}),
	}, nil
}

func (m *BPFMap) Get(key encoding.BinaryMarshaler, value encoding.BinaryUnmarshaler) (bool, error) {
	keyValue, err := m.getKeyOrValue(key, int(m.keySize), _key)
	if err != nil {
		return false, err
	}
	returnValue := make([]byte, m.valueSize)
	_, e := bpfCall(_BPF_MAP_LOOKUP_ELEM,
		unsafe.Pointer(&mapOpAttr{
			mapFd: uint32(m.fd),
			key:   uint64(uintptr(unsafe.Pointer(&keyValue[0]))),
			value: uint64(uintptr(unsafe.Pointer(&returnValue[0]))),
		}), 32)
	if e != 0 {
		if e == syscall.ENOENT {
			return false, nil
		}
		return false, errnoErr(e)
	}
	return true, value.UnmarshalBinary(returnValue)
}

func (m *BPFMap) Create(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) (bool, error) {
	return m.put(key, value, _BPF_NOEXIST)
}

func (m *BPFMap) Put(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) error {
	_, err := m.put(key, value, _BPF_ANY)
	return err
}

func (m *BPFMap) Replace(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) (bool, error) {
	return m.put(key, value, _BPF_EXIST)
}

func (m *BPFMap) Delete(key encoding.BinaryMarshaler) (bool, error) {
	keyValue, err := m.getKeyOrValue(key, int(m.keySize), _key)
	if err != nil {
		return false, err
	}
	_, e := bpfCall(_BPF_MAP_DELETE_ELEM,
		unsafe.Pointer(&mapOpAttr{
			mapFd: uint32(m.fd),
			key:   uint64(uintptr(unsafe.Pointer(&keyValue[0]))),
		}), 32)
	if e == 0 {
		m.keysLock.Lock()
		defer m.keysLock.Unlock()
		delete(m.keys, base64.StdEncoding.EncodeToString(keyValue))
		return true, nil
	}
	if e == syscall.ENOENT {
		return false, nil
	}
	return false, errnoErr(e)
}

func (m *BPFMap) GetNextKey(key encoding.BinaryMarshaler, nextKey encoding.BinaryUnmarshaler) (bool, error) {
	keyValue, err := m.getKeyOrValue(key, int(m.keySize), _key)
	if err != nil {
		return false, err
	}
	returnValue := make([]byte, m.keySize)
	_, e := bpfCall(_BPF_MAP_LOOKUP_ELEM,
		unsafe.Pointer(&mapOpAttr{
			mapFd: uint32(m.fd),
			key:   uint64(uintptr(unsafe.Pointer(&keyValue[0]))),
			value: uint64(uintptr(unsafe.Pointer(&returnValue[0]))),
		}), 32)
	if e != 0 {
		if e == syscall.ENOENT {
			return false, nil
		}
		return false, errnoErr(e)
	}
	return true, nextKey.UnmarshalBinary(returnValue)
}

func (m *BPFMap) GetKeys() []*[]byte {
	m.keysLock.RLock()
	defer m.keysLock.RUnlock()
	keys := make([]*[]byte, len(m.keys))
	i := 0
	for k, _ := range m.keys {
		v, err := base64.StdEncoding.DecodeString(k)
		if err != nil {
			panic(err)
		}
		keys[i] = &v
		i++
	}
	return keys
}

func (m *BPFMap) Close() error {
	return syscall.Close(int(m.fd))
}

func (m *BPFMap) GetMapType() MapType {
	return m.mapType
}

func (m *BPFMap) GetFd() int {
	return m.fd
}

func (m *BPFMap) GetKeySize() uint32 {
	return m.keySize
}

func (m *BPFMap) GetValueSize() uint32 {
	return m.valueSize
}

func (m *BPFMap) GetMaxEntries() uint32 {
	return m.maxEntries
}

func (m *BPFMap) put(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler, putType uint64) (bool, error) {
	keyValue, err := m.getKeyOrValue(key, int(m.keySize), _key)
	if err != nil {
		return false, err
	}
	v, err := m.getKeyOrValue(value, int(m.valueSize), _value)
	if err != nil {
		return false, err
	}
	_, e := bpfCall(_BPF_MAP_UPDATE_ELEM,
		unsafe.Pointer(&mapOpAttr{
			mapFd: uint32(m.fd),
			key:   uint64(uintptr(unsafe.Pointer(&keyValue[0]))),
			value: uint64(uintptr(unsafe.Pointer(&v[0]))),
			flags: putType,
		}), 32)
	if e != 0 {
		switch putType {
		case _BPF_NOEXIST:
			if e == syscall.EEXIST {
				return false, nil
			}
		case _BPF_EXIST:
			if e == syscall.ENOENT {
				return false, nil
			}
		}
		return false, errnoErr(e)
	}
	m.keysLock.Lock()
	defer m.keysLock.Unlock()
	m.keys[base64.StdEncoding.EncodeToString(v)] = struct{}{}
	return true, nil
}

func (m *BPFMap) getKeyOrValue(kv encoding.BinaryMarshaler, size int, typ string) ([]byte, error) {
	v, err := kv.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf := v
	lenV := len(v)
	if lenV > size {
		return nil, fmt.Errorf("%s size is %s, it should be %s", typ, lenV, size)
	} else if lenV < size {
		buf = make([]byte, size)
		copy(buf, v)
	}
	return buf, nil
}

func errnoErr(e syscall.Errno) error {
	switch e {
	case 0:
		return nil
	case syscall.EPERM:
		return fmt.Errorf("operation not permitted")
	case syscall.EINVAL:
		return fmt.Errorf("invalid argument")
	case syscall.ENOMEM:
		return fmt.Errorf("out of memory")
	case syscall.E2BIG:
		return fmt.Errorf("max entries exceeded")
	case syscall.EFAULT:
		return fmt.Errorf("bad address")
	case syscall.EBADF:
		return fmt.Errorf("not an open file descriptor")
	case syscall.EACCES:
		return fmt.Errorf("bpf program rejected as unsafe")
	case syscall.ENOSPC:
		return fmt.Errorf("bpf logging buffer not large enough")
	}
	return e
}

func bpfCall(cmd int, attr unsafe.Pointer, size int) (uintptr, syscall.Errno) {
	r1, _, errNo := syscall.Syscall(uintptr(_BPF_CALL), uintptr(cmd), uintptr(attr), uintptr(size))
	return r1, errNo
}

type mapCreateAttr struct {
	mapType                               MapType
	keySize, valueSize, maxEntries, flags uint32
}

type mapOpAttr struct {
	mapFd   uint32
	padding uint32
	key     uint64
	value   uint64
	flags   uint64
}
