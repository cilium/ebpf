package ebpf

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"

	"github.com/go-quicktest/qt"
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

// newHash returns a new Map of type Hash. Cleanup is handled automatically.
func newHash(t *testing.T) *Map {
	hash, err := NewMap(&MapSpec{
		Type:       Hash,
		KeySize:    5,
		ValueSize:  4,
		MaxEntries: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hash.Close() })
	return hash
}

func TestMap(t *testing.T) {
	m := createArray(t)

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

	sliceVal := make([]uint32, 1)
	qt.Assert(t, qt.IsNil(m.Lookup(uint32(0), sliceVal)))
	qt.Assert(t, qt.DeepEquals(sliceVal, []uint32{42}))

	var slice []byte
	qt.Assert(t, qt.IsNil(m.Lookup(uint32(0), &slice)))
	qt.Assert(t, qt.DeepEquals(slice, internal.NativeEndian.AppendUint32(nil, 42)))

	var k uint32
	if err := m.NextKey(uint32(0), &k); err != nil {
		t.Fatal("Can't get:", err)
	}
	if k != 1 {
		t.Error("Want key 1, got", k)
	}
}

func TestMapBatch(t *testing.T) {
	if err := haveBatchAPI(); err != nil {
		t.Skipf("batch api not available: %v", err)
	}

	contents := map[uint32]uint32{
		0: 42, 1: 4242, 2: 23, 3: 2323,
	}
	mustNewMap := func(mapType MapType, max uint32) *Map {
		m, err := NewMap(&MapSpec{
			Type:       mapType,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: max,
		})
		if err != nil {
			t.Fatal(err)
		}
		return m
	}

	var (
		// Make the map large enough to avoid ENOSPC.
		hashMax  uint32 = uint32(len(contents)) * 10
		arrayMax uint32 = 4
	)

	hash := mustNewMap(Hash, hashMax)
	defer hash.Close()

	array := mustNewMap(Array, arrayMax)
	defer array.Close()

	hashPerCpu := mustNewMap(PerCPUHash, hashMax)
	defer hashPerCpu.Close()

	arrayPerCpu := mustNewMap(PerCPUArray, arrayMax)
	defer arrayPerCpu.Close()

	for _, m := range []*Map{array, hash, arrayPerCpu, hashPerCpu} {
		t.Run(m.Type().String(), func(t *testing.T) {
			if m.Type() == PerCPUArray {
				// https://lore.kernel.org/bpf/20210424214510.806627-2-pctammela@mojatatu.com/
				testutils.SkipOnOldKernel(t, "5.13", "batched ops support for percpu array")
			}
			possibleCPU := 1
			if m.Type().hasPerCPUValue() {
				possibleCPU = MustPossibleCPU()
			}
			var keys, values []uint32
			for key, value := range contents {
				keys = append(keys, key)
				for i := 0; i < possibleCPU; i++ {
					values = append(values, value*uint32((i+1)))
				}
			}

			count, err := m.BatchUpdate(keys, values, nil)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.Equals(count, len(contents)))

			n := len(contents) / 2 // cut buffer in half
			lookupKeys := make([]uint32, n)
			lookupValues := make([]uint32, n*possibleCPU)

			var cursor MapBatchCursor
			var total int
			for {
				count, err = m.BatchLookup(&cursor, lookupKeys, lookupValues, nil)
				total += count
				if errors.Is(err, ErrKeyNotExist) {
					break
				}
				qt.Assert(t, qt.IsNil(err))

				qt.Assert(t, qt.IsTrue(count <= len(lookupKeys)))
				for i, key := range lookupKeys[:count] {
					for j := 0; j < possibleCPU; j++ {
						value := lookupValues[i*possibleCPU+j]
						expected := contents[key] * uint32(j+1)
						qt.Assert(t, qt.Equals(value, expected), qt.Commentf("value for key %d should match", key))
					}
				}
			}
			qt.Assert(t, qt.Equals(total, len(contents)))

			if m.Type() == Array || m.Type() == PerCPUArray {
				// Arrays don't support batch delete
				return
			}

			cursor = MapBatchCursor{}
			total = 0
			for {
				count, err = m.BatchLookupAndDelete(&cursor, lookupKeys, lookupValues, nil)
				total += count
				if errors.Is(err, ErrKeyNotExist) {
					break
				}
				qt.Assert(t, qt.IsNil(err))

				qt.Assert(t, qt.IsTrue(count <= len(lookupKeys)))
				for i, key := range lookupKeys[:count] {
					for j := 0; j < possibleCPU; j++ {
						value := lookupValues[i*possibleCPU+j]
						expected := contents[key] * uint32(j+1)
						qt.Assert(t, qt.Equals(value, expected), qt.Commentf("value for key %d should match", key))
					}
				}
			}
			qt.Assert(t, qt.Equals(total, len(contents)))

			if possibleCPU > 1 {
				values := make([]uint32, possibleCPU)
				qt.Assert(t, qt.ErrorIs(m.Lookup(uint32(0), values), ErrKeyNotExist))
			} else {
				var v uint32
				qt.Assert(t, qt.ErrorIs(m.Lookup(uint32(0), &v), ErrKeyNotExist))
			}
		})
	}
}

func TestMapBatchCursorReuse(t *testing.T) {
	spec := &MapSpec{
		Type:       Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 4,
	}

	arr1, err := NewMap(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer arr1.Close()

	arr2, err := NewMap(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer arr2.Close()

	tmp := make([]uint32, 2)

	var cursor MapBatchCursor
	_, err = arr1.BatchLookup(&cursor, tmp, tmp, nil)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	_, err = arr2.BatchLookup(&cursor, tmp, tmp, nil)
	qt.Assert(t, qt.IsNotNil(err))
}

func TestMapLookupKeyTooSmall(t *testing.T) {
	m := createArray(t)
	defer m.Close()

	var small uint16
	qt.Assert(t, qt.IsNil(m.Put(uint32(0), uint32(1234))))
	qt.Assert(t, qt.IsNotNil(m.Lookup(uint32(0), &small)))
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

	if err := m.Put(uint32(0), uint32(42)); !errors.Is(err, sys.ErrClosedFd) {
		t.Fatal("Put doesn't check for closed fd", err)
	}

	if _, err := m.LookupBytes(uint32(0)); !errors.Is(err, sys.ErrClosedFd) {
		t.Fatal("Get doesn't check for closed fd", err)
	}
}

func TestBatchMapWithLock(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.13", "MAP BATCH BPF_F_LOCK")
	file := testutils.NativeFile(t, "testdata/map_spin_lock-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal("Can't parse ELF:", err)
	}

	coll, err := NewCollection(spec)
	if err != nil {
		t.Fatal("Can't parse ELF:", err)
	}
	defer coll.Close()

	type spinLockValue struct {
		Cnt     uint32
		Padding uint32
	}

	m, ok := coll.Maps["spin_lock_map"]
	if !ok {
		t.Fatal(err)
	}

	keys := []uint32{0, 1}
	values := []spinLockValue{{Cnt: 42}, {Cnt: 4242}}
	count, err := m.BatchUpdate(keys, values, &BatchOptions{ElemFlags: uint64(UpdateLock)})
	if err != nil {
		t.Fatalf("BatchUpdate: %v", err)
	}
	if count != len(keys) {
		t.Fatalf("BatchUpdate: expected count, %d, to be %d", count, len(keys))
	}

	var cursor MapBatchCursor
	lookupKeys := make([]uint32, 2)
	lookupValues := make([]spinLockValue, 2)
	count, err = m.BatchLookup(&cursor, lookupKeys, lookupValues, &BatchOptions{ElemFlags: uint64(LookupLock)})
	if !errors.Is(err, ErrKeyNotExist) {
		t.Fatalf("BatchLookup: %v", err)
	}
	if count != 2 {
		t.Fatalf("BatchLookup: expected two keys, got %d", count)
	}

	cursor = MapBatchCursor{}
	deleteKeys := []uint32{0, 1}
	deleteValues := make([]spinLockValue, 2)
	count, err = m.BatchLookupAndDelete(&cursor, deleteKeys, deleteValues, nil)
	if !errors.Is(err, ErrKeyNotExist) {
		t.Fatalf("BatchLookupAndDelete: %v", err)
	}
	if count != 2 {
		t.Fatalf("BatchLookupAndDelete: expected two keys, got %d", count)
	}
}

func TestMapWithLock(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.13", "MAP BPF_F_LOCK")
	file := testutils.NativeFile(t, "testdata/map_spin_lock-%s.elf")
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		t.Fatal("Can't parse ELF:", err)
	}

	coll, err := NewCollection(spec)
	if err != nil {
		t.Fatal("Can't parse ELF:", err)
	}
	defer coll.Close()

	type spinLockValue struct {
		Cnt     uint32
		Padding uint32
	}

	m, ok := coll.Maps["spin_lock_map"]
	if !ok {
		t.Fatal(err)
	}

	key := uint32(1)
	value := spinLockValue{Cnt: 5}
	err = m.Update(key, value, UpdateLock)
	if err != nil {
		t.Fatal(err)
	}

	value.Cnt = 0
	err = m.LookupWithFlags(&key, &value, LookupLock)
	if err != nil {
		t.Fatal(err)
	}
	if value.Cnt != 5 {
		t.Fatalf("Want value 5, got %d", value.Cnt)
	}

	t.Run("LookupAndDelete", func(t *testing.T) {
		testutils.SkipOnOldKernel(t, "5.14", "LOOKUP_AND_DELETE flags")

		value.Cnt = 0
		err = m.LookupAndDeleteWithFlags(&key, &value, LookupLock)
		if err != nil {
			t.Fatal(err)
		}
		if value.Cnt != 5 {
			t.Fatalf("Want value 5, got %d", value.Cnt)
		}

		err = m.LookupWithFlags(&key, &value, LookupLock)
		if err != nil && !errors.Is(err, ErrKeyNotExist) {
			t.Fatal(err)
		}
	})
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

	if err := m.Put(uint32(0), uint32(42)); err != nil {
		t.Fatal("Can't put:", err)
	}

	tmp := testutils.TempBPFFS(t)
	path := filepath.Join(tmp, "map")

	if err := m.Pin(path); err != nil {
		testutils.SkipIfNotSupported(t, err)
		t.Fatal(err)
	}

	pinned := m.IsPinned()
	qt.Assert(t, qt.IsTrue(pinned))

	m.Close()

	m, err := LoadPinnedMap(path, nil)
	testutils.SkipIfNotSupported(t, err)
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
	testutils.SkipIfNotSupported(t, err)
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
	testutils.SkipOnOldKernel(t, "4.9", "atomic re-pinning was introduced in 4.9 series")

	tmp := testutils.TempBPFFS(t)

	spec := spec1.Copy()

	m1, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
	if err != nil {
		t.Fatal("Can't create map:", err)
	}
	defer m1.Close()
	pinned := m1.IsPinned()
	qt.Assert(t, qt.IsTrue(pinned))

	newPath := filepath.Join(tmp, "bar")
	err = m1.Pin(newPath)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))
	oldPath := filepath.Join(tmp, spec.Name)
	if _, err := os.Stat(oldPath); err == nil {
		t.Fatal("Previous pinned map path still exists:", err)
	}
	m2, err := LoadPinnedMap(newPath, nil)
	qt.Assert(t, qt.IsNil(err))
	pinned = m2.IsPinned()
	qt.Assert(t, qt.IsTrue(pinned))
	defer m2.Close()
}

func TestMapPinWithEmptyPath(t *testing.T) {
	m := createArray(t)

	err := m.Pin("")

	qt.Assert(t, qt.Not(qt.IsNil(err)))
}

func TestMapPinFailReplace(t *testing.T) {
	tmp := testutils.TempBPFFS(t)
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
	qt.Assert(t, qt.IsTrue(m.IsPinned()))
	newPath := filepath.Join(tmp, spec2.Name)

	qt.Assert(t, qt.Not(qt.IsNil(m.Pin(newPath))), qt.Commentf("Pin didn't"+
		" fail new path from replacing an existing path"))
}

func TestMapUnpin(t *testing.T) {
	tmp := testutils.TempBPFFS(t)
	spec := spec1.Copy()

	m, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
	if err != nil {
		t.Fatal("Failed to create map:", err)
	}
	defer m.Close()

	pinned := m.IsPinned()
	qt.Assert(t, qt.IsTrue(pinned))
	path := filepath.Join(tmp, spec.Name)
	m2, err := LoadPinnedMap(path, nil)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))
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

	spec := spec1.Copy()

	m1, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
	qt.Assert(t, qt.IsNil(err))
	defer m1.Close()
	pinned := m1.IsPinned()
	qt.Assert(t, qt.IsTrue(pinned))

	path := filepath.Join(tmp, spec.Name)
	m2, err := LoadPinnedMap(path, nil)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))
	defer m2.Close()
	pinned = m2.IsPinned()
	qt.Assert(t, qt.IsTrue(pinned))
}

func TestMapLoadReusePinned(t *testing.T) {
	for _, typ := range []MapType{Array, Hash, DevMap, DevMapHash} {
		t.Run(typ.String(), func(t *testing.T) {
			if typ == DevMap {
				testutils.SkipOnOldKernel(t, "4.14", "devmap")
			}
			if typ == DevMapHash {
				testutils.SkipOnOldKernel(t, "5.4", "devmap_hash")
			}
			tmp := testutils.TempBPFFS(t)
			spec := &MapSpec{
				Name:       "pinmap",
				Type:       typ,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: 1,
				Pinning:    PinByName,
			}

			m1, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
			qt.Assert(t, qt.IsNil(err))
			defer m1.Close()

			m2, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
			qt.Assert(t, qt.IsNil(err))
			defer m2.Close()
		})
	}
}

func TestMapLoadPinnedUnpin(t *testing.T) {
	tmp := testutils.TempBPFFS(t)

	spec := spec1.Copy()

	m1, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
	qt.Assert(t, qt.IsNil(err))
	defer m1.Close()
	pinned := m1.IsPinned()
	qt.Assert(t, qt.IsTrue(pinned))

	path := filepath.Join(tmp, spec.Name)
	m2, err := LoadPinnedMap(path, nil)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))
	defer m2.Close()
	err = m1.Unpin()
	qt.Assert(t, qt.IsNil(err))
	err = m2.Unpin()
	qt.Assert(t, qt.IsNil(err))
}

func TestMapLoadPinnedWithOptions(t *testing.T) {
	// Introduced in commit 6e71b04a8224.
	testutils.SkipOnOldKernel(t, "4.15", "file_flags in BPF_OBJ_GET")

	array := createArray(t)

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
	qt.Assert(t, qt.IsNil(err))
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
	t.Cleanup(func() { m.Close() })
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
	another, err := NewMapFromFD(dupFD(t, nested.FD()))
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
			var value uint64
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
			var value uint64
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

func TestMapIteratorAllocations(t *testing.T) {
	arr, err := NewMap(&MapSpec{
		Type:       Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer arr.Close()

	var k, v uint32
	iter := arr.Iterate()

	// AllocsPerRun warms up the function for us.
	allocs := testing.AllocsPerRun(1, func() {
		if !iter.Next(&k, &v) {
			t.Fatal("Next failed")
		}
	})

	qt.Assert(t, qt.Equals(allocs, float64(0)))
}

func TestMapBatchLookupAllocations(t *testing.T) {
	testutils.SkipIfNotSupported(t, haveBatchAPI())

	arr, err := NewMap(&MapSpec{
		Type:       Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer arr.Close()

	var cursor MapBatchCursor
	tmp := make([]uint32, 2)
	input := any(tmp)

	// AllocsPerRun warms up the function for us.
	allocs := testing.AllocsPerRun(1, func() {
		_, err := arr.BatchLookup(&cursor, input, input, nil)
		if err != nil {
			t.Fatal(err)
		}
	})

	qt.Assert(t, qt.Equals(allocs, 0))
}

func TestMapIterateHashKeyOneByteFull(t *testing.T) {
	hash, err := NewMap(&MapSpec{
		Type:       Hash,
		KeySize:    1,
		ValueSize:  1,
		MaxEntries: 256,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hash.Close()

	for i := 0; i < int(hash.MaxEntries()); i++ {
		if err := hash.Put(uint8(i), uint8(i)); err != nil {
			t.Fatal(err)
		}
	}
	var key uint8
	var value uint8
	var keys int

	entries := hash.Iterate()
	for entries.Next(&key, &value) {
		if key != value {
			t.Fatalf("Expected key == value, got key %v value %v", key, value)
		}
		keys++
	}

	if err := entries.Err(); err != nil {
		t.Fatal(err)
	}

	if keys != int(hash.MaxEntries()) {
		t.Fatalf("Expected to get %d keys, have %d", hash.MaxEntries(), keys)
	}
}

func TestMapGuessNonExistentKey(t *testing.T) {
	tests := []struct {
		name    string
		mapType MapType
		keys    []uint32
	}{
		{
			"empty", Hash, []uint32{},
		},
		{
			"all zero key", Hash, []uint32{0},
		},
		{
			"all ones key", Hash, []uint32{math.MaxUint32},
		},
		{
			"alternating bits key", Hash, []uint32{0x5555_5555},
		},
		{
			"all special patterns", Hash, []uint32{0, math.MaxUint32, 0x5555_5555},
		},
		{
			"empty", Array, []uint32{},
		},
		{
			"all zero key", Array, []uint32{0},
		},
		{
			"full", Array, []uint32{0, 1},
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s: %s", tt.mapType, tt.name), func(t *testing.T) {
			maxEntries := uint32(len(tt.keys))
			if maxEntries == 0 {
				maxEntries = 1
			}

			m, err := NewMap(&MapSpec{
				Type:       tt.mapType,
				KeySize:    4,
				ValueSize:  4,
				MaxEntries: maxEntries,
			})
			if err != nil {
				t.Fatal(err)
			}
			defer m.Close()

			for _, key := range tt.keys {
				if err := m.Put(key, key); err != nil {
					t.Fatal(err)
				}
			}

			guess, err := m.guessNonExistentKey()
			if err != nil {
				t.Fatal(err)
			}

			if len(guess) != int(m.keySize) {
				t.Fatal("Guessed key has wrong size")
			}

			var value uint32
			if err := m.Lookup(guess, &value); !errors.Is(err, unix.ENOENT) {
				t.Fatal("Doesn't return ENOENT:", err)
			}
		})
	}

	t.Run("Hash: full", func(t *testing.T) {
		const n = math.MaxUint8 + 1

		hash, err := NewMap(&MapSpec{
			Type:       Hash,
			KeySize:    1,
			ValueSize:  1,
			MaxEntries: n,
		})
		if err != nil {
			t.Fatal(err)
		}
		defer hash.Close()

		for i := 0; i < n; i++ {
			if err := hash.Put(uint8(i), uint8(i)); err != nil {
				t.Fatal(err)
			}
		}

		_, err = hash.guessNonExistentKey()
		if err == nil {
			t.Fatal("guessNonExistentKey doesn't return error on full hash table")
		}
	})
}

func TestNotExist(t *testing.T) {
	hash := newHash(t)

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
		t.Error("Deleting unknown key doesn't return ErrKeyNotExist", err)
	}

	var k = []byte{1, 2, 3, 4, 5}
	if err := hash.NextKey(&k, &tmp); !errors.Is(err, ErrKeyNotExist) {
		t.Error("Looking up next key in empty map doesn't return a non-existing error", err)
	}

	if err := hash.NextKey(nil, &tmp); !errors.Is(err, ErrKeyNotExist) {
		t.Error("Looking up next key in empty map doesn't return a non-existing error", err)
	}
}

func TestExist(t *testing.T) {
	hash := newHash(t)

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

	if err := parent.Put(idx, a); err != nil {
		t.Fatal(err)
	}

	var (
		key     uint32
		m       *Map
		entries = parent.Iterate()
	)

	if !entries.Next(&key, &m) {
		t.Fatal("Iterator encountered error:", entries.Err())
	}
	m.Close()

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
			numCPU := MustPossibleCPU()
			if numCPU < 2 {
				t.Skip("Test requires at least two CPUs")
			}
			if typ == PerCPUHash || typ == PerCPUArray {
				testutils.SkipOnOldKernel(t, "4.6", "per-CPU hash and array")
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
			retrievedVal := make([]*customEncoding, numCPU)
			if err := arr.Lookup(uint32(0), retrievedVal); err == nil {
				t.Fatal("Slices with nil values should generate error")
			}
			for i := range retrievedVal {
				retrievedVal[i] = &customEncoding{}
			}
			if err := arr.Lookup(uint32(0), retrievedVal); err != nil {
				t.Fatal("Can't retrieve key 0:", err)
			}
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
	numCPU := MustPossibleCPU()
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

	progAttachAttrs := sys.ProgAttachAttr{
		TargetFdOrIfindex: uint32(cgroup.Fd()),
		AttachBpfFd:       uint32(prog.FD()),
		AttachType:        uint32(AttachCGroupInetEgress),
		AttachFlags:       0,
		ReplaceBpfFd:      0,
	}
	err = sys.ProgAttach(&progAttachAttrs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		attr := sys.ProgDetachAttr{
			TargetFdOrIfindex: uint32(cgroup.Fd()),
			AttachBpfFd:       uint32(prog.FD()),
			AttachType:        uint32(AttachCGroupInetEgress),
		}
		if err := sys.ProgDetach(&attr); err != nil {
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

	var info sys.MapInfo
	if err := sys.ObjInfo(m.fd, &info); err != nil {
		t.Fatal(err)
	}

	if name := unix.ByteSliceToString(info.Name[:]); name != "test" {
		t.Error("Expected name to be test, got", name)
	}
}

func TestMapFromFD(t *testing.T) {
	m := createArray(t)

	if err := m.Put(uint32(0), uint32(123)); err != nil {
		t.Fatal(err)
	}

	// If you're thinking about copying this, don't. Use
	// Clone() instead.
	m2, err := NewMapFromFD(dupFD(t, m.FD()))
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer m2.Close()

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

	// Ensure there is at least one map on the system.
	_ = newHash(t)

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
			if !errors.Is(err, os.ErrNotExist) {
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
	hash := newHash(t)

	info, err := hash.Info()
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Couldn't get map info:", err)
	}

	id, ok := info.ID()
	if !ok {
		t.Skip("Map ID not supported")
	}

	hash2, err := NewMapFromID(id)
	if err != nil {
		t.Fatalf("Can't get map for ID %d: %v", id, err)
	}
	hash2.Close()

	// As there can be multiple maps, we use max(uint32) as MapID to trigger an expected error.
	_, err = NewMapFromID(MapID(math.MaxUint32))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Expected ErrNotExist, got:", err)
	}
}

func TestMapPinning(t *testing.T) {
	tmp := testutils.TempBPFFS(t)

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
	qt.Assert(t, qt.IsTrue(pinned))

	m1Info, err := m1.Info()
	qt.Assert(t, qt.IsNil(err))

	if err := m1.Put(uint32(0), uint32(42)); err != nil {
		t.Fatal("Can't write value:", err)
	}

	m2, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Can't create map:", err)
	}
	defer m2.Close()

	m2Info, err := m2.Info()
	qt.Assert(t, qt.IsNil(err))

	if m1ID, ok := m1Info.ID(); ok {
		m2ID, _ := m2Info.ID()
		qt.Assert(t, qt.Equals(m2ID, m1ID))
	}

	var value uint32
	if err := m2.Lookup(uint32(0), &value); err != nil {
		t.Fatal("Can't read from map:", err)
	}

	if value != 42 {
		t.Fatal("Pinning doesn't use pinned maps")
	}

	spec.KeySize = 8
	spec.ValueSize = 8
	m3, err := NewMapWithOptions(spec, MapOptions{PinPath: tmp})
	if err == nil {
		m3.Close()
		t.Fatalf("Opening a pinned map with a mismatching spec did not fail")
	}
	if !errors.Is(err, ErrMapIncompatible) {
		t.Fatalf("Opening a pinned map with a mismatching spec failed with the wrong error")
	}

	// Check if error string mentions both KeySize and ValueSize.
	qt.Assert(t, qt.StringContains(err.Error(), "KeySize"))
	qt.Assert(t, qt.StringContains(err.Error(), "ValueSize"))
}

func TestPerfEventArrayCompatible(t *testing.T) {
	ms := &MapSpec{
		Type: PerfEventArray,
	}

	m, err := NewMap(ms)
	qt.Assert(t, qt.IsNil(err))
	defer m.Close()

	qt.Assert(t, qt.IsNil(ms.Compatible(m)))

	ms.MaxEntries = m.MaxEntries() - 1
	qt.Assert(t, qt.IsNotNil(ms.Compatible(m)))
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

type benchKey struct {
	id uint64
}

func (bk *benchKey) MarshalBinary() ([]byte, error) {
	buf := make([]byte, 8)
	internal.NativeEndian.PutUint64(buf, bk.id)
	return buf, nil
}

func BenchmarkMarshaling(b *testing.B) {
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
	b.Cleanup(func() { m.Close() })

	b.Run("ValueUnmarshalReflect", func(b *testing.B) {
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

	b.Run("KeyMarshalReflect", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		var value benchValue

		for i := 0; i < b.N; i++ {
			err := m.Lookup(&key, unsafe.Pointer(&value))
			if err != nil {
				b.Fatal("Can't get key:", err)
			}
		}
	})

	b.Run("ValueBinaryUnmarshaler", func(b *testing.B) {
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

	b.Run("KeyBinaryMarshaler", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()

		var key benchKey
		var value customBenchValue

		for i := 0; i < b.N; i++ {
			err := m.Lookup(&key, unsafe.Pointer(&value))
			if err != nil {
				b.Fatal("Can't get key:", err)
			}
		}
	})

	b.Run("KeyValueUnsafe", func(b *testing.B) {
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
	key := uint64(1)
	val := make([]uint64, MustPossibleCPU())
	for i := range val {
		val[i] = uint64(i)
	}

	m, err := NewMap(&MapSpec{
		Type:       PerCPUHash,
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: 1,
	})
	if err != nil {
		b.Fatal(err)
	}

	b.Cleanup(func() { m.Close() })
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
	b.Cleanup(func() { m.Close() })

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

func BenchmarkIterate(b *testing.B) {
	for _, mt := range []MapType{Hash, PerCPUHash} {
		m, err := NewMap(&MapSpec{
			Type:       mt,
			KeySize:    8,
			ValueSize:  8,
			MaxEntries: 1000,
		})
		if err != nil {
			b.Fatal(err)
		}
		b.Cleanup(func() {
			m.Close()
		})
		possibleCPU := 1
		if m.Type().hasPerCPUValue() {
			possibleCPU = MustPossibleCPU()
		}
		var (
			n      = m.MaxEntries()
			keys   = make([]uint64, n)
			values = make([]uint64, n*uint32(possibleCPU))
		)

		for i := 0; uint32(i) < n; i++ {
			keys[i] = uint64(i)
			for j := 0; j < possibleCPU; j++ {
				values[i] = uint64((i * possibleCPU) + j)
			}
		}

		_, err = m.BatchUpdate(keys, values, nil)
		testutils.SkipIfNotSupported(b, err)
		qt.Assert(b, qt.IsNil(err))

		b.Run(m.Type().String(), func(b *testing.B) {
			b.Run("MapIterator", func(b *testing.B) {
				var k uint64
				v := make([]uint64, possibleCPU)

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					iter := m.Iterate()
					for iter.Next(&k, v) {
						continue
					}
					if err := iter.Err(); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("MapIteratorDelete", func(b *testing.B) {
				var k uint64
				v := make([]uint64, possibleCPU)

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					b.StopTimer()
					if _, err := m.BatchUpdate(keys, values, nil); err != nil {
						b.Fatal(err)
					}
					b.StartTimer()

					iter := m.Iterate()
					for iter.Next(&k, &v) {
						if err := m.Delete(&k); err != nil {
							b.Fatal(err)
						}
					}
					if err := iter.Err(); err != nil {
						b.Fatal(err)
					}
				}
			})

			b.Run("BatchLookup", func(b *testing.B) {
				k := make([]uint64, m.MaxEntries())
				v := make([]uint64, m.MaxEntries()*uint32(possibleCPU))

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					var cursor MapBatchCursor
					for {
						_, err := m.BatchLookup(&cursor, k, v, nil)
						if errors.Is(err, ErrKeyNotExist) {
							break
						}
						if err != nil {
							b.Fatal(err)
						}
					}
				}
			})

			b.Run("BatchLookupAndDelete", func(b *testing.B) {
				k := make([]uint64, m.MaxEntries())
				v := make([]uint64, m.MaxEntries()*uint32(possibleCPU))

				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					b.StopTimer()
					if _, err := m.BatchUpdate(keys, values, nil); err != nil {
						b.Fatal(err)
					}
					b.StartTimer()

					var cursor MapBatchCursor
					for {
						_, err := m.BatchLookupAndDelete(&cursor, k, v, nil)
						if errors.Is(err, ErrKeyNotExist) {
							break
						}
						if err != nil {
							b.Fatal(err)
						}
					}
				}
			})

			b.Run("BatchDelete", func(b *testing.B) {
				b.ReportAllocs()
				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					b.StopTimer()
					if _, err := m.BatchUpdate(keys, values, nil); err != nil {
						b.Fatal(err)
					}
					b.StartTimer()

					if _, err := m.BatchDelete(keys, nil); err != nil {
						b.Fatal(err)
					}
				}
			})
		})
	}
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
	defer arr.Close()

	possibleCPUs := MustPossibleCPU()
	perCPUValues := map[uint32]uint32{
		0: 4,
		1: 5,
	}

	for k, v := range perCPUValues {
		// We set each perCPU slots to the same value.
		values := make([]uint32, possibleCPUs)
		for i := range values {
			values[i] = v
		}
		if err := arr.Put(k, values); err != nil {
			panic(err)
		}
	}

	for k := 0; k < 2; k++ {
		var values []uint32
		if err := arr.Lookup(uint32(k), &values); err != nil {
			panic(err)
		}
		// Note we will print an unexpected message if this is not true.
		fmt.Printf("Value of key %v on all CPUs: %v\n", k, values[0])
	}
	var (
		key     uint32
		entries = arr.Iterate()
	)

	var values []uint32
	for entries.Next(&key, &values) {
		expected, ok := perCPUValues[key]
		if !ok {
			fmt.Printf("Unexpected key %v\n", key)
			continue
		}

		for i, n := range values {
			if n != expected {
				fmt.Printf("Key %v, Value for cpu %v is %v not %v\n",
					key, i, n, expected)
			}
		}
	}

	if err := entries.Err(); err != nil {
		panic(err)
	}
	// Output:
	// Value of key 0 on all CPUs: 4
	// Value of key 1 on all CPUs: 5
}

// It is possible to use unsafe.Pointer to avoid marshalling
// and copy overhead. It is the responsibility of the caller to ensure
// the correct size of unsafe.Pointers.
//
// Note that using unsafe.Pointer is only marginally faster than
// implementing Marshaler on the type.
func ExampleMap_zeroCopy() {
	hash, err := NewMap(&MapSpec{
		Type:       Hash,
		KeySize:    5,
		ValueSize:  4,
		MaxEntries: 10,
	})
	if err != nil {
		panic(err)
	}
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

func ExampleMap_NextKey() {
	hash, err := NewMap(&MapSpec{
		Type:       Hash,
		KeySize:    5,
		ValueSize:  4,
		MaxEntries: 10,
		Contents: []MapKV{
			{"hello", uint32(21)},
			{"world", uint32(42)},
		},
	})
	if err != nil {
		panic(err)
	}
	defer hash.Close()

	var cur, next string
	var keys []string

	for err = hash.NextKey(nil, &next); ; err = hash.NextKey(cur, &next) {
		if errors.Is(err, ErrKeyNotExist) {
			break
		}
		if err != nil {
			panic(err)
		}
		keys = append(keys, next)
		cur = next
	}

	// Order of keys is non-deterministic due to randomized map seed
	sort.Strings(keys)
	fmt.Printf("Keys are %v\n", keys)
	// Output: Keys are [hello world]
}

// ExampleMap_Iterate demonstrates how to iterate over all entries
// in a map.
func ExampleMap_Iterate() {
	hash, err := NewMap(&MapSpec{
		Type:       Hash,
		KeySize:    5,
		ValueSize:  4,
		MaxEntries: 10,
		Contents: []MapKV{
			{"hello", uint32(21)},
			{"world", uint32(42)},
		},
	})
	if err != nil {
		panic(err)
	}
	defer hash.Close()

	var (
		key     string
		value   uint32
		entries = hash.Iterate()
	)

	values := make(map[string]uint32)
	for entries.Next(&key, &value) {
		// Order of keys is non-deterministic due to randomized map seed
		values[key] = value
	}

	if err := entries.Err(); err != nil {
		panic(fmt.Sprint("Iterator encountered an error:", err))
	}

	for k, v := range values {
		fmt.Printf("key: %s, value: %d\n", k, v)
	}

	// Unordered output:
	// key: hello, value: 21
	// key: world, value: 42
}

// It is possible to iterate nested maps and program arrays by
// unmarshaling into a *Map or *Program.
func ExampleMap_Iterate_nestedMapsAndProgramArrays() {
	inner := &MapSpec{
		Type:       Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
		Contents: []MapKV{
			{uint32(0), uint32(1)},
			{uint32(1), uint32(2)},
		},
	}
	im, err := NewMap(inner)
	if err != nil {
		panic(err)
	}
	defer im.Close()

	outer := &MapSpec{
		Type:       ArrayOfMaps,
		InnerMap:   inner,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 10,
		Contents: []MapKV{
			{uint32(0), im},
		},
	}
	arrayOfMaps, err := NewMap(outer)
	if errors.Is(err, internal.ErrNotSupported) {
		// Fake the output if on very old kernel.
		fmt.Println("outerKey: 0")
		fmt.Println("\tinnerKey 0 innerValue 1")
		fmt.Println("\tinnerKey 1 innerValue 2")
		return
	}
	if err != nil {
		panic(err)
	}
	defer arrayOfMaps.Close()

	var (
		key     uint32
		m       *Map
		entries = arrayOfMaps.Iterate()
	)
	for entries.Next(&key, &m) {
		// Make sure that the iterated map is closed after
		// we are done.
		defer m.Close()

		// Order of keys is non-deterministic due to randomized map seed
		fmt.Printf("outerKey: %v\n", key)

		var innerKey, innerValue uint32
		items := m.Iterate()
		for items.Next(&innerKey, &innerValue) {
			fmt.Printf("\tinnerKey %v innerValue %v\n", innerKey, innerValue)
		}
		if err := items.Err(); err != nil {
			panic(fmt.Sprint("Inner Iterator encountered an error:", err))
		}
	}

	if err := entries.Err(); err != nil {
		panic(fmt.Sprint("Iterator encountered an error:", err))
	}
	// Output:
	// outerKey: 0
	//	innerKey 0 innerValue 1
	// 	innerKey 1 innerValue 2
}
