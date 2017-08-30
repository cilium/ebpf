// Copyright 2017 Nathan Sweet. All rights reserved.
// Use of this source code is governed by a BSD-style
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

type MapType uint32

const (
	Hash MapType = 1 + iota
	Array
	ProgramArray
	PerfEventArray
	PerCPUHash
	PerCPUArray
	StackTrace
	CGroupArray
	LRUHash
	LRUCPUHash
)

const (
	_BPF_MAP_CREATE = iota
	_BPF_MAP_LOOKUP_ELEM
	_BPF_MAP_UPDATE_ELEM
	_BPF_MAP_DELETE_ELEM
	_BPF_MAP_GET_NEXT_KEY
	_BPF_PROG_LOAD
	_BPF_OBJ_PIN
	_BPF_OBJ_GET
	_BPF_PROG_ATTACH
	_BPF_PROG_DETACH
	_BPF_PROG_TEST_RUN
	_BPF_PROG_GET_NEXT_ID
	_BPF_MAP_GET_NEXT_ID
	_BPF_PROG_GET_FD_BY_ID
	_BPF_MAP_GET_FD_BY_ID
	_BPF_OBJ_GET_INFO_BY_FD

	_BPF_ANY = iota
	_BPF_NOEXIST
	_BPF_EXIST
)

const (
	_key   = "key"
	_value = "value"
)

type EBPFMap interface {
	Get(encoding.BinaryMarshaler, encoding.BinaryUnmarshaler) (bool, error)
	Create(encoding.BinaryMarshaler, encoding.BinaryMarshaler) (bool, error)
	Put(encoding.BinaryMarshaler, encoding.BinaryMarshaler) (bool, error)
	Replace(encoding.BinaryMarshaler, encoding.BinaryMarshaler) (bool, error)
	Delete(encoding.BinaryMarshaler) (bool, error)
	GetNextKey(encoding.BinaryMarshaler, encoding.BinaryUnmarshaler) (bool, error)
	GetKeys() []*[]byte
}

type eMap struct {
	mapType    MapType
	fd         uintptr
	keySize    uint32
	valueSize  uint32
	maxEntries uint32

	keys     map[string]struct{}
	keysLock sync.RWMutex
}

func NewEBPFMap(mapType MapType, keySize, valueSize, maxEntries uint32) (EBPFMap, error) {
	fd, e := bpfCall(_BPF_MAP_CREATE, unsafe.Pointer(&mapCreateAttr{mapType, keySize, valueSize, maxEntries}), 16)
	err := errnoErr(e)
	if err != nil {
		return nil, fmt.Errorf("map create: %s", err.Error())
	}
	return &eMap{
		mapType:    mapType,
		fd:         fd,
		keySize:    keySize,
		valueSize:  valueSize,
		maxEntries: maxEntries,
		keys:       make(map[string]struct{}),
	}, nil
}

func (m *eMap) Get(key encoding.BinaryMarshaler, value encoding.BinaryUnmarshaler) (bool, error) {
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

func (m *eMap) Create(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) (bool, error) {
	return m.put(key, value, _BPF_NOEXIST)
}

func (m *eMap) Put(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) (bool, error) {
	return m.put(key, value, _BPF_ANY)
}

func (m *eMap) Replace(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) (bool, error) {
	return m.put(key, value, _BPF_EXIST)
}

func (m *eMap) Delete(key encoding.BinaryMarshaler) (bool, error) {
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

func (m *eMap) GetNextKey(key encoding.BinaryMarshaler, nextKey encoding.BinaryUnmarshaler) (bool, error) {
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

func (m *eMap) GetKeys() []*[]byte {
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

func (m *eMap) put(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler, putType uint64) (bool, error) {
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

func (m *eMap) getKeyOrValue(kv encoding.BinaryMarshaler, size int, typ string) ([]byte, error) {
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
	mapType                        MapType
	keySize, valueSize, maxEntries uint32
}

type mapOpAttr struct {
	mapFd   uint32
	padding uint32
	key     uint64
	value   uint64
	flags   uint64
}
