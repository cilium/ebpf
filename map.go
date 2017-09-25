// Copyright 2017 Nathan Sweet. All rights reserved.
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
package ebpf

import (
	"encoding"
	"fmt"
	"syscall"
	"unsafe"
)

type BPFMapSpec interface {
	MapType() MapType
	KeySize() uint32
	ValueSize() uint32
	MaxEntries() uint32
	Flags() uint32
}

type BPFMap int

func NewBPFMap(mapType MapType, keySize, valueSize, maxEntries, flags uint32) (BPFMap, error) {
	fd, e := bpfCall(_BPF_MAP_CREATE, unsafe.Pointer(&mapCreateAttr{mapType, keySize, valueSize, maxEntries, flags}), 20)
	err := bpfErrNo(e)
	if err != nil {
		return BPFMap(-1), fmt.Errorf("map create: %s", err.Error())
	}
	return BPFMap(fd), nil
}

func NewBPFMapFromSpec(spec BPFMapSpec) (BPFMap, error) {
	return NewBPFMap(spec.MapType(), spec.KeySize(), spec.ValueSize(), spec.MaxEntries(), spec.Flags())
}

func (m BPFMap) Get(key encoding.BinaryMarshaler, value encoding.BinaryUnmarshaler, valueSize int) (bool, error) {
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

func (m BPFMap) GetRaw(key encoding.BinaryMarshaler, value *[]byte) (bool, error) {
	keyValue, err := key.MarshalBinary()
	if err != nil {
		return false, err
	}
	_, e := bpfCall(_BPF_MAP_LOOKUP_ELEM,
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

func (m BPFMap) Create(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) (bool, error) {
	return m.put(key, value, _BPF_NOEXIST)
}

func (m BPFMap) Put(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) error {
	_, err := m.put(key, value, _BPF_ANY)
	return err
}

func (m BPFMap) Replace(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler) (bool, error) {
	return m.put(key, value, _BPF_EXIST)
}

func (m BPFMap) Delete(key encoding.BinaryMarshaler) (bool, error) {
	keyValue, err := key.MarshalBinary()
	if err != nil {
		return false, err
	}
	_, e := bpfCall(_BPF_MAP_DELETE_ELEM,
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

func (m BPFMap) GetNextKey(key encoding.BinaryMarshaler, nextKey encoding.BinaryUnmarshaler, keySize int) (bool, error) {
	v := make([]byte, keySize)
	ok, err := m.GetRaw(key, &v)
	if err != nil || !ok {
		return ok, err
	}
	err = nextKey.UnmarshalBinary(v)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (m BPFMap) GetNextKeyRaw(key encoding.BinaryMarshaler, nextKey *[]byte) (bool, error) {
	keyValue, err := key.MarshalBinary()
	if err != nil {
		return false, err
	}
	_, e := bpfCall(_BPF_MAP_LOOKUP_ELEM,
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

func (m BPFMap) Close() error {
	return syscall.Close(m.GetFd())
}

func (m BPFMap) GetFd() int {
	return int(m)
}

func (m BPFMap) Pin(fileName string) error {
	return pinObject(fileName, uint32(m))
}

func LoadBPFMap(fileName string) (BPFMap, error) {
	ptr, err := getObject(fileName)
	return BPFMap(ptr), err
}

func (m BPFMap) put(key encoding.BinaryMarshaler, value encoding.BinaryMarshaler, putType uint64) (bool, error) {
	keyValue, err := key.MarshalBinary()
	if err != nil {
		return false, err
	}
	v, err := value.MarshalBinary()
	if err != nil {
		return false, err
	}
	_, e := bpfCall(_BPF_MAP_UPDATE_ELEM,
		unsafe.Pointer(&mapOpAttr{
			mapFd: uint32(m),
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
		return false, bpfErrNo(e)
	}
	return true, nil
}
