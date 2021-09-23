package ebpf

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/btf"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"

	qt "github.com/frankban/quicktest"
)

var (
	spec1 = &MapSpec{
		Name:       "foo",
		Type:       Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		Pinning:    PinByName,
	}
)

func TestMap(t *testing.T) {
	m := createArray(t)
	defer m.Close()

	t.Log(m)

	if err := m.Put(uint32(0), uint32(42)); err != nil {
		t.Fatal("Can't put:", err)
	}
	if err := m.Put(uint32(1), uint32(4242)); err != nil {
		t.Fatal("Can't put:", err)
	}

	m2, err := m.Clone()
	if err != nil {
		t.Fatal("Can't clone map:", err)
	}
	defer m2.Close()

	m.Close()
	m = m2

	var v uint32
	if err := m.Lookup(uint32(0), &v); err != nil {
		t.Fatal("Can't lookup 0:", err)
	}
	if v != 42 {
		t.Error("Want value 42, got", v)
	}

	var k uint32
	if err := m.NextKey(uint32(0), &k); err != nil {
		t.Fatal("Can't get:", err)
	}
	if k != 1 {
		t.Error("Want key 1, got", k)
	}
}

func TestBatchAPIArray(t *testing.T) {
	if err := haveBatchAPI(); err != nil {
		t.Skipf("batch api not available: %v", err)
	}
	m, err := NewMap(&MapSpec{
		Type:       Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	var (
		nextKey      uint32
		keys         = []uint32{0, 1}
		values       = []uint32{42, 4242}
		lookupKeys   = make([]uint32, 2)
		lookupValues = make([]uint32, 2)
		deleteKeys   = make([]uint32, 2)
		deleteValues = make([]uint32, 2)
	)

	count, err := m.BatchUpdate(keys, values, nil)
	if err != nil {
		t.Fatalf("BatchUpdate: %v", err)
	}
	if count != len(keys) {
		t.Fatalf("BatchUpdate: expected count, %d, to be %d", count, len(keys))
	}

	var v uint32
	if err := m.Lookup(uint32(0), &v); err != nil {
		t.Fatal("Can't lookup 0:", err)
	}
	if v != 42 {
		t.Error("Want value 42, got", v)
	}

	count, err = m.BatchLookup(nil, &nextKey, lookupKeys, lookupValues, nil)
	if err != nil {
		t.Fatalf("BatchLookup: %v", err)
	}
	if count != len(lookupKeys) {
		t.Fatalf("BatchLookup: returned %d results, expected %d", count, len(lookupKeys))
	}
	if nextKey != lookupKeys[1] {
		t.Fatalf("BatchLookup: expected nextKey, %d, to be the same as the lastKey returned, %d", nextKey, lookupKeys[1])
	}
	if !reflect.DeepEqual(keys, lookupKeys) {
		t.Errorf("BatchUpdate and BatchLookup keys disagree: %v %v", keys, lookupKeys)
	}
	if !reflect.DeepEqual(values, lookupValues) {
		t.Errorf("BatchUpdate and BatchLookup values disagree: %v %v", values, lookupValues)
	}

	_, err = m.BatchLookupAndDelete(nil, &nextKey, deleteKeys, deleteValues, nil)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("BatchLookUpDelete: expected error %v, but got %v", ErrNotSupported, err)
	}
}

func TestBatchAPIHash(t *testing.T) {
	if err := haveBatchAPI(); err != nil {
		t.Skipf("batch api not available: %v", err)
	}
	m, err := NewMap(&MapSpec{
		Type:       Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	var (
		nextKey      uint32
		keys         = []uint32{0, 1}
		values       = []uint32{42, 4242}
		lookupKeys   = make([]uint32, 2)
		lookupValues = make([]uint32, 2)
		deleteKeys   = make([]uint32, 2)
		deleteValues = make([]uint32, 2)
	)

	count, err := m.BatchUpdate(keys, values, nil)
	if err != nil {
		t.Fatalf("BatchUpdate: %v", err)
	}
	if count != len(keys) {
		t.Fatalf("BatchUpdate: expected count, %d, to be %d", count, len(keys))
	}

	var v uint32
	if err := m.Lookup(uint32(0), &v); err != nil {
		t.Fatal("Can't lookup 0:", err)
	}
	if v != 42 {
		t.Error("Want value 42, got", v)
	}

	count, err = m.BatchLookup(nil, &nextKey, lookupKeys, lookupValues, nil)
	if !errors.Is(err, ErrKeyNotExist) {
		t.Fatalf("BatchLookup: expected %v got %v", ErrKeyNotExist, err)
	}
	if count != len(lookupKeys) {
		t.Fatalf("BatchLookup: returned %d results, expected %d", count, len(lookupKeys))
	}
	sort.Slice(lookupKeys, func(i, j int) bool { return lookupKeys[i] < lookupKeys[j] })
	if !reflect.DeepEqual(keys, lookupKeys) {
		t.Errorf("BatchUpdate and BatchLookup keys disagree: %v %v", keys, lookupKeys)
	}
	sort.Slice(lookupValues, func(i, j int) bool { return lookupValues[i] < lookupValues[j] })
	if !reflect.DeepEqual(values, lookupValues) {
		t.Errorf("BatchUpdate and BatchLookup values disagree: %v %v", values, lookupValues)
	}

	count, err = m.BatchLookupAndDelete(nil, &nextKey, deleteKeys, deleteValues, nil)
	if !errors.Is(err, ErrKeyNotExist) {
		t.Fatalf("BatchLookupAndDelete: expected %v got %v", ErrKeyNotExist, err)
	}
	if count != len(deleteKeys) {
		t.Fatalf("BatchLookupAndDelete: returned %d results, expected %d", count, len(deleteKeys))
	}
	sort.Slice(deleteKeys, func(i, j int) bool { return deleteKeys[i] < deleteKeys[j] })
	if !reflect.DeepEqual(keys, deleteKeys) {
		t.Errorf("BatchUpdate and BatchLookupAndDelete keys disagree: %v %v", keys, deleteKeys)
	}
	sort.Slice(deleteValues, func(i, j int) bool { return deleteValues[i] < deleteValues[j] })
	if !reflect.DeepEqual(values, deleteValues) {
		t.Errorf("BatchUpdate and BatchLookupAndDelete values disagree: %v %v", values, deleteValues)
	}

	if err := m.Lookup(uint32(0), &v); !errors.Is(err, ErrKeyNotExist) {
		t.Fatalf("Lookup should have failed with error, %v, instead error is %v", ErrKeyNotExist, err)
	}
}

func TestBatchAPIMapDelete(t *testing.T) {
	if err := haveBatchAPI(); err != nil {
		t.Skipf("batch api not available: %v", err)
	}
	m, err := NewMap(&MapSpec{
		Type:       Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	var (
		keys   = []uint32{0, 1}
		values = []uint32{42, 4242}
	)

	count, err := m.BatchUpdate(keys, values, nil)
	if err != nil {
		t.Fatalf("BatchUpdate: %v", err)
	}
	if count != len(keys) {
		t.Fatalf("BatchUpdate: expected count, %d, to be %d", count, len(keys))
	}

	var v uint32
	if err := m.Lookup(uint32(0), &v); err != nil {
		t.Fatal("Can't lookup 0:", err)
	}
	if v != 42 {
		t.Error("Want value 42, got", v)
	}

	count, err = m.BatchDelete(keys, nil)
	if err != nil {
		t.Fatalf("BatchDelete: %v", err)
	}
	if count != len(keys) {
		t.Fatalf("BatchDelete: expected %d deletions got %d", len(keys), count)
	}

	if err := m.Lookup(uint32(0), &v); !errors.Is(err, ErrKeyNotExist) {
		t.Fatalf("Lookup should have failed with error, %v, instead error is %v", ErrKeyNotExist, err)
	}
}

func TestMapClose(t *testing.T) {
	m := createArray(t)

	if err := m.Close(); err != nil {
		t.Fatal("Can't close map:", err)
	}

	if err := m.Put(uint32(0), uint32(42)); !errors.Is(err, internal.ErrClosedFd) {
		t.Fatal("Put doesn't check for closed fd", err)
	}

	if _, err := m.LookupBytes(uint32(0)); !errors.Is(err, internal.ErrClosedFd) {
		t.Fatal("Get doesn't check for closed fd", err)
	}
}

func TestMapCloneNil(t *testing.T) {
	m, err := (*Map)(nil).Clone()
	if err != nil {
		t.Fatal(err)
	}

	if m != nil {
		t.Fatal("Cloning a nil map doesn't return nil")
	}
}

func TestMapPin(t *testing.T) {
	m := createArray(t)
	c := qt.New(t)
	defer m.Close()

	if err := m.Put(uint32(0), uint32(42)); err != nil {
		t.Fatal("Can't put:", err)
	}

	tmp := testutils.TempBPFFS(t)
	path := filepath.Join(tmp, "map")

	if err := m.Pin(path); err != nil {
		t.Fatal(err)
	}

	pinned := m.IsPinned()
	c.Assert(pinned, qt.Equals, true)

	m.Close()

	m, err := LoadPinnedMap(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	var v uint32
	if err := m.Lookup(uint32(0), &v); err != nil {
		t.Fatal("Can't lookup 0:", err)
	}
	if v != 42 {
		t.Error("Want value 42, got", v)
	}
}

func TestNestedMapPin(t *testing.T) {
	m, err := NewMap(&MapSpec{
		Type:       ArrayOfMaps,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
		InnerMap: &MapSpec{
			Type:       Array,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 1,
		},
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	tmp, err := os.MkdirTemp("/sys/fs/bpf", "ebpf-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	path := filepath.Join(tmp, "nested")
	if err := m.Pin(path); err != nil {
		t.Fatal(err)
	}
	m.Close()

	m, err = LoadPinnedMap(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
}

func TestNestedMapPinNested(t *testing.T) {
	if _, err := NewMap(&MapSpec{
		Type:       ArrayOfMaps,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
		InnerMap: &MapSpec{
			Name:       "inner",
			Type:       Array,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 1,
			Pinning:    PinByName,
		},
	}); err == nil {
		t.Error("Inner maps should not be pinnable")
	}
}

func TestMapPinMultiple(t *testing.T) {
	tmp := testutils.TempBPFFS(t)
	c := qt.New(t)

	spec := spec1.Copy()

	m1, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
	if err != nil {
		t.Fatal("Can't create map:", err)
	}
	defer m1.Close()
	pinned := m1.IsPinned()
	c.Assert(pinned, qt.Equals, true)

	newPath := filepath.Join(tmp, "bar")
	err = m1.Pin(newPath)
	c.Assert(err, qt.IsNil)
	oldPath := filepath.Join(tmp, spec.Name)
	if _, err := os.Stat(oldPath); err == nil {
		t.Fatal("Previous pinned map path still exists:", err)
	}
	m2, err := LoadPinnedMap(newPath, nil)
	c.Assert(err, qt.IsNil)
	defer m2.Close()
}

func TestMapPinWithEmptyPath(t *testing.T) {
	m := createArray(t)
	c := qt.New(t)
	defer m.Close()

	err := m.Pin("")

	c.Assert(err, qt.Not(qt.IsNil))
}

func TestMapPinFailReplace(t *testing.T) {
	tmp := testutils.TempBPFFS(t)
	c := qt.New(t)
	spec := spec1.Copy()
	spec2 := spec1.Copy()
	spec2.Name = spec1.Name + "bar"

	m, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
	if err != nil {
		t.Fatal("Failed to create map:", err)
	}
	defer m.Close()
	m2, err := NewMapWithOptions(spec2, MapOptions{PinPath: tmp})
	if err != nil {
		t.Fatal("Failed to create map2:", err)
	}
	defer m2.Close()
	c.Assert(m.IsPinned(), qt.Equals, true)
	newPath := filepath.Join(tmp, spec2.Name)

	c.Assert(m.Pin(newPath), qt.Not(qt.IsNil), qt.Commentf("Pin didn't"+
		" fail new path from replacing an existing path"))
}

func TestMapUnpin(t *testing.T) {
	tmp := testutils.TempBPFFS(t)
	c := qt.New(t)
	spec := spec1.Copy()

	m, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
	if err != nil {
		t.Fatal("Failed to create map:", err)
	}
	defer m.Close()

	pinned := m.IsPinned()
	c.Assert(pinned, qt.Equals, true)
	path := filepath.Join(tmp, spec.Name)
	m2, err := LoadPinnedMap(path, nil)
	c.Assert(err, qt.IsNil)
	defer m2.Close()

	if err = m.Unpin(); err != nil {
		t.Fatal("Failed to unpin map:", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("Pinned map path still exists after unpinning:", err)
	}
}

func TestMapLoadPinned(t *testing.T) {
	tmp := testutils.TempBPFFS(t)
	c := qt.New(t)

	spec := spec1.Copy()

	m1, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
	c.Assert(err, qt.IsNil)
	defer m1.Close()
	pinned := m1.IsPinned()
	c.Assert(pinned, qt.Equals, true)

	path := filepath.Join(tmp, spec.Name)
	m2, err := LoadPinnedMap(path, nil)
	c.Assert(err, qt.IsNil)
	defer m2.Close()
	pinned = m2.IsPinned()
	c.Assert(pinned, qt.Equals, true)
}

func TestMapLoadPinnedUnpin(t *testing.T) {
	tmp := testutils.TempBPFFS(t)
	c := qt.New(t)

	spec := spec1.Copy()

	m1, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
	c.Assert(err, qt.IsNil)
	defer m1.Close()
	pinned := m1.IsPinned()
	c.Assert(pinned, qt.Equals, true)

	path := filepath.Join(tmp, spec.Name)
	m2, err := LoadPinnedMap(path, nil)
	c.Assert(err, qt.IsNil)
	defer m2.Close()
	err = m1.Unpin()
	c.Assert(err, qt.IsNil)
	err = m2.Unpin()
	c.Assert(err, qt.IsNil)
}

func TestMapLoadPinnedWithOptions(t *testing.T) {
	// Introduced in commit 6e71b04a8224.
	testutils.SkipOnOldKernel(t, "4.14", "file_flags in BPF_OBJ_GET")

	array := createArray(t)
	defer array.Close()

	tmp := testutils.TempBPFFS(t)

	path := filepath.Join(tmp, "map")
	if err := array.Pin(path); err != nil {
		t.Fatal(err)
	}
	if err := array.Put(uint32(0), uint32(123)); err != nil {
		t.Fatal(err)
	}
	array.Close()

	t.Run("read-only", func(t *testing.T) {
		array, err := LoadPinnedMap(path, &LoadPinOptions{
			ReadOnly: true,
		})
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal("Can't load map:", err)
		}
		defer array.Close()

		if err := array.Put(uint32(0), uint32(1)); !errors.Is(err, unix.EPERM) {
			t.Fatal("Expected EPERM from Put, got", err)
		}
	})

	t.Run("write-only", func(t *testing.T) {
		array, err := LoadPinnedMap(path, &LoadPinOptions{
			WriteOnly: true,
		})
		testutils.SkipIfNotSupported(t, err)
		if err != nil {
			t.Fatal("Can't load map:", err)
		}
		defer array.Close()

		var value uint32
		if err := array.Lookup(uint32(0), &value); !errors.Is(err, unix.EPERM) {
			t.Fatal("Expected EPERM from Lookup, got", err)
		}
	})
}

func TestMapPinFlags(t *testing.T) {
	tmp := testutils.TempBPFFS(t)

	spec := &MapSpec{
		Name:       "map",
		Type:       Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		Pinning:    PinByName,
	}

	m, err := NewMapWithOptions(spec, MapOptions{
		PinPath: tmp,
	})
	qt.Assert(t, err, qt.IsNil)
	m.Close()

	_, err = NewMapWithOptions(spec, MapOptions{
		PinPath: tmp,
		LoadPinOptions: LoadPinOptions{
			Flags: math.MaxUint32,
		},
	})
	if !errors.Is(err, unix.EINVAL) {
		t.Fatal("Invalid flags should trigger EINVAL:", err)
	}
}

func createArray(t *testing.T) *Map {
	t.Helper()

	m, err := NewMap(&MapSpec{
		Type:       Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMapQueue(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.20", "map type queue")

	m, err := NewMap(&MapSpec{
		Type:       Queue,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	for _, v := range []uint32{42, 4242} {
		if err := m.Put(nil, v); err != nil {
			t.Fatalf("Can't put %d: %s", v, err)
		}
	}

	var v uint32
	if err := m.LookupAndDelete(nil, &v); err != nil {
		t.Fatal("Can't lookup and delete element:", err)
	}
	if v != 42 {
		t.Error("Want value 42, got", v)
	}

	v = 0
	if err := m.LookupAndDelete(nil, unsafe.Pointer(&v)); err != nil {
		t.Fatal("Can't lookup and delete element using unsafe.Pointer:", err)
	}
	if v != 4242 {
		t.Error("Want value 4242, got", v)
	}

	if err := m.LookupAndDelete(nil, &v); !errors.Is(err, ErrKeyNotExist) {
		t.Fatal("Lookup and delete on empty Queue:", err)
	}
}

func TestMapInMap(t *testing.T) {
	for _, typ := range []MapType{ArrayOfMaps, HashOfMaps} {
		t.Run(typ.String(), func(t *testing.T) {
			spec := &MapSpec{
				Type:       typ,
				KeySize:    4,
				MaxEntries: 2,
				InnerMap: &MapSpec{
					Type:       Array,
					KeySize:    4,
					ValueSize:  4,
					MaxEntries: 2,
				},
			}

			inner, err := NewMap(spec.InnerMap)
			if err != nil {
				t.Fatal(err)
			}
			if err := inner.Put(uint32(1), uint32(4242)); err != nil {
				t.Fatal(err)
			}
			defer inner.Close()

			outer, err := NewMap(spec)
			testutils.SkipIfNotSupported(t, err)
			if err != nil {
				t.Fatal(err)
			}
			defer outer.Close()

			if err := outer.Put(uint32(0), inner); err != nil {
				t.Fatal("Can't put inner map:", err)
			}

			var inner2 *Map
			if err := outer.Lookup(uint32(0), &inner2); err != nil {
				t.Fatal("Can't lookup 0:", err)
			}
			defer inner2.Close()

			var v uint32
			if err := inner2.Lookup(uint32(1), &v); err != nil {
				t.Fatal("Can't lookup 1 in inner2:", err)
			}

			if v != 4242 {
				t.Error("Expected value 4242, got", v)
			}

			inner2.Close()

			// Make sure we can still access the original map
			if err := inner.Lookup(uint32(1), &v); err != nil {
				t.Fatal("Can't lookup 1 in inner:", err)
			}

			if v != 4242 {
				t.Error("Expected value 4242, got", v)
			}
		})
	}
}

func TestNewMapInMapFromFD(t *testing.T) {
	nested, err := NewMap(&MapSpec{
		Type:       ArrayOfMaps,
		KeySize:    4,
		MaxEntries: 2,
		InnerMap: &MapSpec{
			Type:       Array,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 2,
		},
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer nested.Close()

	// Do not copy this, use Clone instead.
	another, err := NewMapFromFD(nested.FD())
	if err != nil {
		t.Fatal("Can't create a new nested map from an FD")
	}
	another.Close()
}

func TestPerfEventArray(t *testing.T) {
	specs := []*MapSpec{
		{Type: PerfEventArray},
		{Type: PerfEventArray, KeySize: 4},
		{Type: PerfEventArray, ValueSize: 4},
	}

	for _, spec := range specs {
		m, err := NewMap(spec)
		if err != nil {
			t.Errorf("Can't create perf event array from %v: %s", spec, err)
		} else {
			m.Close()
		}
	}
}

func createMapInMap(t *testing.T, typ MapType) *Map {
	t.Helper()

	spec := &MapSpec{
		Type:       typ,
		KeySize:    4,
		MaxEntries: 2,
		InnerMap: &MapSpec{
			Type:       Array,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 2,
		},
	}

	m, err := NewMap(spec)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMapInMapValueSize(t *testing.T) {
	spec := &MapSpec{
		Type:       ArrayOfMaps,
		KeySize:    4,
		ValueSize:  0,
		MaxEntries: 2,
		InnerMap: &MapSpec{
			Type:       Array,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 2,
		},
	}

	m, err := NewMap(spec)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	m.Close()

	spec.ValueSize = 4
	m, err = NewMap(spec)
	if err != nil {
		t.Fatal(err)
	}
	m.Close()

	spec.ValueSize = 1
	if _, err := NewMap(spec); err == nil {
		t.Fatal("Expected an error")
	}
}

func TestIterateEmptyMap(t *testing.T) {
	makeMap := func(t *testing.T, mapType MapType) *Map {
		m, err := NewMap(&MapSpec{
			Type:       mapType,
			KeySize:    4,
			ValueSize:  8,
			MaxEntries: 2,
		})
		if errors.Is(err, unix.EINVAL) {
			t.Skip(mapType, "is not supported")
		}
		if err != nil {
			t.Fatal("Can't create map:", err)
		}
		t.Cleanup(func() { m.Close() })
		return m
	}

	for _, mapType := range []MapType{
		Hash,
		SockHash,
	} {
		t.Run(mapType.String(), func(t *testing.T) {
			m := makeMap(t, mapType)
			entries := m.Iterate()

			var key string
			var value uint32
			if entries.Next(&key, &value) != false {
				t.Error("Empty hash should not be iterable")
			}
			if err := entries.Err(); err != nil {
				t.Error("Empty hash shouldn't return an error:", err)
			}
		})
	}

	for _, mapType := range []MapType{
		Array,
		SockMap,
	} {
		t.Run(mapType.String(), func(t *testing.T) {
			m := makeMap(t, mapType)
			entries := m.Iterate()
			var key string
			var value uint32
			for entries.Next(&key, &value) {
				// Some empty arrays like sockmap don't return any keys.
			}
			if err := entries.Err(); err != nil {
				t.Error("Empty array shouldn't return an error:", err)
			}
		})
	}
}

func TestMapIterate(t *testing.T) {
	hash, err := NewMap(&MapSpec{
		Type:       Hash,
		KeySize:    5,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hash.Close()

	if err := hash.Put("hello", uint32(21)); err != nil {
		t.Fatal(err)
	}

	if err := hash.Put("world", uint32(42)); err != nil {
		t.Fatal(err)
	}

	var key string
	var value uint32
	var keys []string

	entries := hash.Iterate()
	for entries.Next(&key, &value) {
		keys = append(keys, key)
	}

	if err := entries.Err(); err != nil {
		t.Fatal(err)
	}

	sort.Strings(keys)

	if n := len(keys); n != 2 {
		t.Fatal("Expected to get 2 keys, have", n)
	}
	if keys[0] != "hello" {
		t.Error("Expected index 0 to be hello, got", keys[0])
	}
	if keys[1] != "world" {
		t.Error("Expected index 1 to be hello, got", keys[1])
	}
}

func TestNotExist(t *testing.T) {
	hash := createHash()
	defer hash.Close()

	var tmp uint32
	err := hash.Lookup("hello", &tmp)
	if !errors.Is(err, ErrKeyNotExist) {
		t.Error("Lookup doesn't return ErrKeyNotExist")
	}

	buf, err := hash.LookupBytes("hello")
	if err != nil {
		t.Error("Looking up non-existent key return an error:", err)
	}
	if buf != nil {
		t.Error("LookupBytes returns non-nil buffer for non-existent key")
	}

	if err := hash.Delete("hello"); !errors.Is(err, ErrKeyNotExist) {
		t.Error("Deleting unknown key doesn't return ErrKeyNotExist")
	}

	if err := hash.NextKey(nil, &tmp); !errors.Is(err, ErrKeyNotExist) {
		t.Error("Looking up next key in empty map doesn't return a non-existing error")
	}
}

func TestExist(t *testing.T) {
	hash := createHash()
	defer hash.Close()

	if err := hash.Put("hello", uint32(21)); err != nil {
		t.Errorf("Failed to put key/value pair into hash: %v", err)
	}

	if err := hash.Update("hello", uint32(42), UpdateNoExist); !errors.Is(err, ErrKeyExist) {
		t.Error("Updating existing key doesn't return ErrKeyExist")
	}
}

func TestIterateMapInMap(t *testing.T) {
	const idx = uint32(1)

	parent := createMapInMap(t, ArrayOfMaps)
	defer parent.Close()

	a := createArray(t)
	defer a.Close()

	if err := parent.Put(idx, a); err != nil {
		t.Fatal(err)
	}

	var (
		key     uint32
		m       *Map
		entries = parent.Iterate()
	)
	defer m.Close()

	if !entries.Next(&key, &m) {
		t.Fatal("Iterator encountered error:", entries.Err())
	}

	if key != 1 {
		t.Error("Iterator didn't skip first entry")
	}

	if m == nil {
		t.Fatal("Map is nil")
	}
}

func TestPerCPUMarshaling(t *testing.T) {
	for _, typ := range []MapType{PerCPUHash, PerCPUArray, LRUCPUHash} {
		t.Run(typ.String(), func(t *testing.T) {
			numCPU, err := internal.PossibleCPUs()
			if err != nil {
				t.Fatal(err)
			}
			if numCPU < 2 {
				t.Skip("Test requires at least two CPUs")
			}
			if typ == LRUCPUHash {
				testutils.SkipOnOldKernel(t, "4.10", "LRU per-CPU hash")
			}

			arr, err := NewMap(&MapSpec{
				Type:       typ,
				KeySize:    4,
				ValueSize:  5,
				MaxEntries: 1,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer arr.Close()

			values := []*customEncoding{
				{"hello"},
				{"world"},
			}
			if err := arr.Put(uint32(0), values); err != nil {
				t.Fatal(err)
			}

			// Make sure unmarshaling works on slices containing pointers
			var retrieved []*customEncoding
			if err := arr.Lookup(uint32(0), &retrieved); err != nil {
				t.Fatal("Can't retrieve key 0:", err)
			}

			for i, want := range []string{"HELLO", "WORLD"} {
				if retrieved[i] == nil {
					t.Error("First item is nil")
				} else if have := retrieved[i].data; have != want {
					t.Errorf("Put doesn't use BinaryMarshaler, expected %s but got %s", want, have)
				}
			}

		})
	}
}

type bpfCgroupStorageKey struct {
	CgroupInodeId uint64
	AttachType    AttachType
	_             [4]byte // Padding
}

func TestCgroupPerCPUStorageMarshaling(t *testing.T) {
	numCPU, err := internal.PossibleCPUs()
	if err != nil {
		t.Fatal(err)
	}
	if numCPU < 2 {
		t.Skip("Test requires at least two CPUs")
	}
	testutils.SkipOnOldKernel(t, "5.9", "per-CPU CGoup storage with write from user space support")

	cgroup := testutils.CreateCgroup(t)

	arr, err := NewMap(&MapSpec{
		Type:      PerCPUCGroupStorage,
		KeySize:   uint32(unsafe.Sizeof(bpfCgroupStorageKey{})),
		ValueSize: uint32(unsafe.Sizeof(uint64(0))),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		arr.Close()
	})

	prog, err := NewProgram(&ProgramSpec{
		Type:       CGroupSKB,
		AttachType: AttachCGroupInetEgress,
		License:    "MIT",
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R1, arr.FD()),
			asm.Mov.Imm(asm.R2, 0),
			asm.FnGetLocalStorage.Call(),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	progAttachAttrs := internal.BPFProgAttachAttr{
		TargetFd:     uint32(cgroup.Fd()),
		AttachBpfFd:  uint32(prog.FD()),
		AttachType:   uint32(AttachCGroupInetEgress),
		AttachFlags:  0,
		ReplaceBpfFd: 0,
	}
	err = internal.BPFProgAttach(&progAttachAttrs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		attr := internal.BPFProgDetachAttr{
			TargetFd:    uint32(cgroup.Fd()),
			AttachBpfFd: uint32(prog.FD()),
			AttachType:  uint32(AttachCGroupInetEgress),
		}
		if err := internal.BPFProgDetach(&attr); err != nil {
			t.Fatal(err)
		}
	}()

	var mapKey = &bpfCgroupStorageKey{
		CgroupInodeId: testutils.GetCgroupIno(t, cgroup),
		AttachType:    AttachCGroupInetEgress,
	}

	values := []uint64{1, 2}
	if err := arr.Put(mapKey, values); err != nil {
		t.Fatalf("Can't set cgroup %s storage: %s", cgroup.Name(), err)
	}

	var retrieved []uint64
	if err := arr.Lookup(mapKey, &retrieved); err != nil {
		t.Fatalf("Can't retrieve cgroup %s storage: %s", cgroup.Name(), err)
	}

	for i, want := range []uint64{1, 2} {
		if retrieved[i] == 0 {
			t.Errorf("Item %d is 0", i)
		} else if have := retrieved[i]; have != want {
			t.Errorf("PerCPUCGroupStorage map is not correctly unmarshaled, expected %d but got %d", want, have)
		}
	}
}

func TestMapMarshalUnsafe(t *testing.T) {
	m, err := NewMap(&MapSpec{
		Type:       Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	key := uint32(1)
	value := uint32(42)

	if err := m.Put(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		t.Fatal(err)
	}

	var res uint32
	if err := m.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&res)); err != nil {
		t.Fatal("Can't get item:", err)
	}

	var sum uint32
	iter := m.Iterate()
	for iter.Next(&key, unsafe.Pointer(&res)) {
		sum += res
	}
	if err := iter.Err(); err != nil {
		t.Fatal(err)
	}

	if res != 42 {
		t.Fatalf("Expected 42, got %d", res)
	}

	iter = m.Iterate()
	iter.Next(unsafe.Pointer(&key), &res)
	if err := iter.Err(); err != nil {
		t.Error(err)
	}
	if key != 1 {
		t.Errorf("Expected key 1, got %d", key)
	}

	if err := m.Delete(unsafe.Pointer(&key)); err != nil {
		t.Fatal("Can't delete:", err)
	}
}

func TestMapName(t *testing.T) {
	if err := haveObjName(); err != nil {
		t.Skip(err)
	}

	m, err := NewMap(&MapSpec{
		Name:       "test",
		Type:       Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	info, err := bpfGetMapInfoByFD(m.fd)
	if err != nil {
		t.Fatal(err)
	}

	if name := internal.CString(info.name[:]); name != "test" {
		t.Error("Expected name to be test, got", name)
	}
}

func TestMapFromFD(t *testing.T) {
	m := createArray(t)
	defer m.Close()

	if err := m.Put(uint32(0), uint32(123)); err != nil {
		t.Fatal(err)
	}

	// If you're thinking about copying this, don't. Use
	// Clone() instead.
	m2, err := NewMapFromFD(m.FD())
	if err != nil {
		t.Fatal(err)
	}

	// Both m and m2 refer to the same fd now. Closing either of them will
	// release the fd to the OS, which then might re-use that fd for another
	// test. Once we close the second map we might close the re-used fd
	// inadvertently, leading to spurious test failures.
	// To avoid this we have to "leak" one of the maps.
	m2.fd.Forget()

	var val uint32
	if err := m2.Lookup(uint32(0), &val); err != nil {
		t.Fatal("Can't look up key:", err)
	}

	if val != 123 {
		t.Error("Wrong value")
	}
}

func TestMapContents(t *testing.T) {
	spec := &MapSpec{
		Type:       Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
		Contents: []MapKV{
			{uint32(0), uint32(23)},
			{uint32(1), uint32(42)},
		},
	}

	m, err := NewMap(spec)
	if err != nil {
		t.Fatal("Can't create map:", err)
	}
	defer m.Close()

	var value uint32
	if err := m.Lookup(uint32(0), &value); err != nil {
		t.Error("Can't look up key 0:", err)
	} else if value != 23 {
		t.Errorf("Incorrect value for key 0, expected 23, have %d", value)
	}

	if err := m.Lookup(uint32(1), &value); err != nil {
		t.Error("Can't look up key 1:", err)
	} else if value != 42 {
		t.Errorf("Incorrect value for key 0, expected 23, have %d", value)
	}

	spec.Contents = []MapKV{
		// Key is larger than MaxEntries
		{uint32(14), uint32(0)},
	}

	if _, err = NewMap(spec); err == nil {
		t.Error("Invalid contents should be rejected")
	}
}

func TestMapFreeze(t *testing.T) {
	arr := createArray(t)
	defer arr.Close()

	err := arr.Freeze()
	testutils.SkipIfNotSupported(t, err)

	if err != nil {
		t.Fatal("Can't freeze map:", err)
	}

	if err := arr.Put(uint32(0), uint32(1)); err == nil {
		t.Error("Freeze doesn't prevent modification from user space")
	}
}

func TestMapGetNextID(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.13", "bpf_map_get_next_id")
	var next MapID
	var err error

	hash := createHash()
	defer hash.Close()

	if next, err = MapGetNextID(MapID(0)); err != nil {
		t.Fatal("Can't get next ID:", err)
	}
	if next == MapID(0) {
		t.Fatal("Expected next ID other than 0")
	}

	// As there can be multiple eBPF maps, we loop over all of them and
	// make sure, the IDs increase and the last call will return ErrNotExist
	for {
		last := next
		if next, err = MapGetNextID(last); err != nil {
			if !errors.Is(err, ErrNotExist) {
				t.Fatal("Expected ErrNotExist, got:", err)
			}
			break
		}
		if next <= last {
			t.Fatalf("Expected next ID (%d) to be higher than the last ID (%d)", next, last)
		}
	}
}

func TestNewMapFromID(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.13", "bpf_map_get_fd_by_id")

	hash := createHash()
	defer hash.Close()
	var next MapID
	var err error

	next, err = hash.ID()
	if err != nil {
		t.Fatal("Could not get ID of map:", err)
	}

	if _, err = NewMapFromID(next); err != nil {
		t.Fatalf("Can't get map for ID %d: %v", uint32(next), err)
	}

	// As there can be multiple maps, we use max(uint32) as MapID to trigger an expected error.
	_, err = NewMapFromID(MapID(math.MaxUint32))
	if !errors.Is(err, ErrNotExist) {
		t.Fatal("Expected ErrNotExist, got:", err)
	}
}

func TestMapPinning(t *testing.T) {
	tmp := testutils.TempBPFFS(t)
	c := qt.New(t)

	spec := &MapSpec{
		Name:       "test",
		Type:       Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		Pinning:    PinByName,
	}

	m1, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
	if err != nil {
		t.Fatal("Can't create map:", err)
	}
	defer m1.Close()
	pinned := m1.IsPinned()
	c.Assert(pinned, qt.Equals, true)

	if err := m1.Put(uint32(0), uint32(42)); err != nil {
		t.Fatal("Can't write value:", err)
	}

	// This is a terrible hack: if loading a pinned map tries to load BTF,
	// it will get a nil *btf.Spec from this *btf.Map. This is turn will make
	// btf.NewHandle fail.
	spec.BTF = new(btf.Map)

	m2, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
	if err != nil {
		t.Fatal("Can't create map:", err)
	}
	defer m2.Close()

	var value uint32
	if err := m2.Lookup(uint32(0), &value); err != nil {
		t.Fatal("Can't read from map:", err)
	}

	if value != 42 {
		t.Fatal("Pinning doesn't use pinned maps")
	}

	spec.KeySize = 8
	m3, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
	if err == nil {
		m3.Close()
		t.Fatalf("Opening a pinned map with a mismatching spec did not fail")
	}
	if !errors.Is(err, ErrMapIncompatible) {
		t.Fatalf("Opening a pinned map with a mismatching spec failed with the wrong error")
	}
}

type benchValue struct {
	ID      uint32
	Val16   uint16
	Val16_2 uint16
	Name    [8]byte
	LID     uint64
}

type customBenchValue benchValue

func (cbv *customBenchValue) UnmarshalBinary(buf []byte) error {
	cbv.ID = internal.NativeEndian.Uint32(buf)
	cbv.Val16 = internal.NativeEndian.Uint16(buf[4:])
	cbv.Val16_2 = internal.NativeEndian.Uint16(buf[6:])
	copy(cbv.Name[:], buf[8:])
	cbv.LID = internal.NativeEndian.Uint64(buf[16:])
	return nil
}

func (cbv *customBenchValue) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 24)
	internal.NativeEndian.PutUint32(buf, cbv.ID)
	internal.NativeEndian.PutUint16(buf[4:], cbv.Val16)
	internal.NativeEndian.PutUint16(buf[6:], cbv.Val16_2)
	copy(buf[8:], cbv.Name[:])
	internal.NativeEndian.PutUint64(buf[16:], cbv.LID)
	return buf, nil
}

func BenchmarkMarshalling(b *testing.B) {
	newMap := func(valueSize uint32) *Map {
		m, err := NewMap(&MapSpec{
			Type:       Hash,
			KeySize:    8,
			ValueSize:  valueSize,
			MaxEntries: 1,
		})
		if err != nil {
			b.Fatal(err)
		}
		return m
	}

	key := uint64(0)

	m := newMap(24)
	if err := m.Put(key, benchValue{}); err != nil {
		b.Fatal(err)
	}

	b.Run("reflection", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		var value benchValue

		for i := 0; i < b.N; i++ {
			err := m.Lookup(unsafe.Pointer(&key), &value)
			if err != nil {
				b.Fatal("Can't get key:", err)
			}
		}
	})

	b.Run("custom", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		var value customBenchValue

		for i := 0; i < b.N; i++ {
			err := m.Lookup(unsafe.Pointer(&key), &value)
			if err != nil {
				b.Fatal("Can't get key:", err)
			}
		}
	})

	b.Run("unsafe", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		var value benchValue

		for i := 0; i < b.N; i++ {
			err := m.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value))
			if err != nil {
				b.Fatal("Can't get key:", err)
			}
		}
	})
}

func BenchmarkPerCPUMarshalling(b *testing.B) {
	newMap := func(valueSize uint32) *Map {
		m, err := NewMap(&MapSpec{
			Type:       PerCPUHash,
			KeySize:    8,
			ValueSize:  valueSize,
			MaxEntries: 1,
		})
		if err != nil {
			b.Fatal(err)
		}
		return m
	}

	key := uint64(1)
	val := []uint64{1, 2, 3, 4, 5, 6, 7, 8}

	m := newMap(8)
	if err := m.Put(key, val[0:]); err != nil {
		b.Fatal(err)
	}

	b.Run("reflection", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		var value []uint64

		for i := 0; i < b.N; i++ {
			err := m.Lookup(unsafe.Pointer(&key), &value)
			if err != nil {
				b.Fatal("Can't get key:", err)
			}
		}
	})
}

func BenchmarkMap(b *testing.B) {
	m, err := NewMap(&MapSpec{
		Type:       Hash,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		b.Fatal(err)
	}

	if err := m.Put(uint32(0), uint32(42)); err != nil {
		b.Fatal(err)
	}

	b.Run("Lookup", func(b *testing.B) {
		var key, value uint32

		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			err := m.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Update", func(b *testing.B) {
		var key, value uint32

		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			err := m.Update(unsafe.Pointer(&key), unsafe.Pointer(&value), UpdateAny)
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("NextKey", func(b *testing.B) {
		var key uint32

		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			err := m.NextKey(nil, unsafe.Pointer(&key))
			if err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("Delete", func(b *testing.B) {
		var key uint32

		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			err := m.Delete(unsafe.Pointer(&key))
			if err != nil && !errors.Is(err, ErrKeyNotExist) {
				b.Fatal(err)
			}
		}
	})
}

// Per CPU maps store a distinct value for each CPU. They are useful
// to collect metrics.
func ExampleMap_perCPU() {
	arr, err := NewMap(&MapSpec{
		Type:       PerCPUArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
	})
	if err != nil {
		panic(err)
	}

	first := []uint32{4, 5}
	if err := arr.Put(uint32(0), first); err != nil {
		panic(err)
	}

	second := []uint32{2, 8}
	if err := arr.Put(uint32(1), second); err != nil {
		panic(err)
	}

	var values []uint32
	if err := arr.Lookup(uint32(0), &values); err != nil {
		panic(err)
	}
	fmt.Println("First two values:", values[:2])

	var (
		key     uint32
		entries = arr.Iterate()
	)

	for entries.Next(&key, &values) {
		// NB: sum can overflow, real code should check for this
		var sum uint32
		for _, n := range values {
			sum += n
		}
		fmt.Printf("Sum of %d: %d\n", key, sum)
	}

	if err := entries.Err(); err != nil {
		panic(err)
	}
}

// It is possible to use unsafe.Pointer to avoid marshalling
// and copy overhead. It is the resposibility of the caller to ensure
// the correct size of unsafe.Pointers.
//
// Note that using unsafe.Pointer is only marginally faster than
// implementing Marshaler on the type.
func ExampleMap_zeroCopy() {
	hash := createHash()
	defer hash.Close()

	key := [5]byte{'h', 'e', 'l', 'l', 'o'}
	value := uint32(23)

	if err := hash.Put(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		panic(err)
	}

	value = 0
	if err := hash.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		panic("can't get value:" + err.Error())
	}

	fmt.Printf("The value is: %d\n", value)
	// Output: The value is: 23
}

func createHash() *Map {
	hash, err := NewMap(&MapSpec{
		Type:       Hash,
		KeySize:    5,
		ValueSize:  4,
		MaxEntries: 10,
	})
	if err != nil {
		panic(err)
	}
	return hash
}

func ExampleMap_NextKey() {
	hash := createHash()
	defer hash.Close()

	if err := hash.Put("hello", uint32(21)); err != nil {
		panic(err)
	}

	if err := hash.Put("world", uint32(42)); err != nil {
		panic(err)
	}

	var firstKey string
	if err := hash.NextKey(nil, &firstKey); err != nil {
		panic(err)
	}

	var nextKey string
	if err := hash.NextKey(firstKey, &nextKey); err != nil {
		panic(err)
	}

	// Order of keys is non-deterministic due to randomized map seed
}

// ExampleMap_Iterate demonstrates how to iterate over all entries
// in a map.
func ExampleMap_Iterate() {
	hash := createHash()
	defer hash.Close()

	if err := hash.Put("hello", uint32(21)); err != nil {
		panic(err)
	}

	if err := hash.Put("world", uint32(42)); err != nil {
		panic(err)
	}

	var (
		key     string
		value   uint32
		entries = hash.Iterate()
	)

	for entries.Next(&key, &value) {
		// Order of keys is non-deterministic due to randomized map seed
		fmt.Printf("key: %s, value: %d\n", key, value)
	}

	if err := entries.Err(); err != nil {
		panic(fmt.Sprint("Iterator encountered an error:", err))
	}
}

// It is possible to iterate nested maps and program arrays by
// unmarshaling into a *Map or *Program.
func ExampleMap_Iterate_nestedMapsAndProgramArrays() {
	var arrayOfMaps *Map // Set this up somehow

	var (
		key     uint32
		m       *Map
		entries = arrayOfMaps.Iterate()
	)

	// Make sure that the iterated map is closed after
	// we are done.
	defer m.Close()

	for entries.Next(&key, &m) {
		// Order of keys is non-deterministic due to randomized map seed
		fmt.Printf("key: %v, map: %v\n", key, m)
	}

	if err := entries.Err(); err != nil {
		panic(fmt.Sprint("Iterator encountered an error:", err))
	}
}
