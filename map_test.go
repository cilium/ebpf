package ebpf

import (
	"fmt"
	"io/ioutil"
	"math"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"testing"
)

func TestMain(m *testing.M) {
	err := syscall.Setrlimit(8, &syscall.Rlimit{
		Cur: math.MaxUint64,
		Max: math.MaxUint64,
	})
	if err != nil {
		fmt.Println("WARNING: Failed to adjust rlimit, tests may fail")
	}
	os.Exit(m.Run())
}

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
	if ok, err := m.Get(uint32(0), &v); err != nil {
		t.Fatal("Can't get:", err)
	} else if !ok {
		t.Fatal("Key doesn't exist")
	}
	if v != 42 {
		t.Error("Want value 42, got", v)
	}

	var k uint32
	if ok, err := m.NextKey(uint32(0), &k); err != nil {
		t.Fatal("Can't get:", err)
	} else if !ok {
		t.Fatal("Key doesn't exist")
	}
	if k != 1 {
		t.Error("Want key 1, got", k)
	}
}

func TestMapPin(t *testing.T) {
	m := createArray(t)
	defer m.Close()

	if err := m.Put(uint32(0), uint32(42)); err != nil {
		t.Fatal("Can't put:", err)
	}

	tmp, err := ioutil.TempDir("/sys/fs/bpf", "ebpf-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	path := filepath.Join(tmp, "map")
	if err := m.Pin(path); err != nil {
		t.Fatal(err)
	}
	m.Close()

	m, err = LoadPinnedMap(path)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	var v uint32
	if ok, err := m.Get(uint32(0), &v); err != nil {
		t.Fatal("Can't get:", err)
	} else if !ok {
		t.Fatal("Key doesn't exist")
	}
	if v != 42 {
		t.Error("Want value 42, got", v)
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
			if err != nil {
				t.Fatal(err)
			}
			defer outer.Close()

			if err := outer.Put(uint32(0), inner); err != nil {
				t.Fatal("Can't put inner map:", err)
			}

			var inner2 *Map
			if ok, err := outer.Get(uint32(0), &inner2); err != nil {
				t.Fatal(err)
			} else if !ok {
				t.Fatal("Missing key 0")
			}
			defer inner2.Close()

			var v uint32
			if ok, err := inner2.Get(uint32(1), &v); err != nil {
				t.Fatal(err, inner)
			} else if !ok {
				t.Fatal("Missing key 0")
			}

			if v != 4242 {
				t.Error("Expected value 4242, got", v)
			}

			inner2.Close()

			// Make sure we can still access the original map
			if ok, err := inner.Get(uint32(1), &v); err != nil {
				t.Fatal(err, inner)
			} else if !ok {
				t.Fatal("Missing key 0 from inner")
			}

			if v != 4242 {
				t.Error("Expected value 4242, got", v)
			}
		})
	}
}

func TestMapInMapABI(t *testing.T) {
	m := createMapInMap(t, ArrayOfMaps)
	defer m.Close()

	if m.abi.InnerMap == nil {
		t.Error("ABI is missing InnerMap")
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
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestIterateEmptyMap(t *testing.T) {
	hash := createHash()
	defer hash.Close()

	entries := hash.Iterate()

	var key string
	var value uint32
	if entries.Next(&key, &value) != false {
		t.Error("Empty map should not be iterable")
	}
}

func TestMapIterate(t *testing.T) {
	hash := createHash()
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

	if keys[0] != "hello" {
		t.Error("Expected index 0 to be hello, got", keys[0])
	}
	if keys[1] != "world" {
		t.Error("Expected index 1 to be hello, got", keys[1])
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
	numCPU, err := possibleCPUs()
	if err != nil {
		t.Fatal(err)
	}
	if numCPU < 2 {
		t.Skip("Test requires at least two CPUs")
	}

	arr, err := NewMap(&MapSpec{
		Type:       PerCPUArray,
		KeySize:    4,
		ValueSize:  5,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer arr.Close()

	values := []*customEncoding{
		&customEncoding{"hello"},
		&customEncoding{"world"},
	}
	if err := arr.Put(uint32(0), values); err != nil {
		t.Fatal(err)
	}

	// Make sure unmarshaling works on slices containing pointers
	var retrieved []*customEncoding
	if ok, err := arr.Get(uint32(0), &retrieved); err != nil {
		t.Fatal(err)
	} else if !ok {
		t.Fatal("Can't retrieve key 0")
	}

	for i, want := range []string{"HELLO", "WORLD"} {
		if retrieved[i] == nil {
			t.Error("First item is nil")
		} else if have := retrieved[i].data; have != want {
			t.Errorf("Put doesn't use BinaryMarshaler, expected %s but got %s", want, have)
		}
	}
}

func TestMapName(t *testing.T) {
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

	if name := convertCString(info.mapName[:]); name != "test" {
		t.Error("Expected name to be test, got", name)
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

	first := []uint32{4, 5}
	if err := arr.Put(uint32(0), first); err != nil {
		panic(err)
	}

	second := []uint32{2, 8}
	if err := arr.Put(uint32(1), second); err != nil {
		panic(err)
	}

	var values []uint32
	if ok, err := arr.Get(uint32(0), &values); err != nil {
		panic(err)
	} else if !ok {
		panic("item 0 not found")
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
	if ok, err := hash.NextKey(nil, &firstKey); err != nil {
		panic(err)
	} else if !ok {
		panic("map is empty")
	}

	var nextKey string
	if ok, err := hash.NextKey(firstKey, &nextKey); err != nil {
		panic(err)
	} else if !ok {
		panic("no keys after " + firstKey)
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
