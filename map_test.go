package ebpf

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestMap(t *testing.T) {
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

	t.Log(m)

	if err := m.Put(uint32(0), uint32(42)); err != nil {
		t.Fatal("Can't put:", err)
	}
	if err := m.Put(uint32(1), uint32(4242)); err != nil {
		t.Fatal("Can't put:", err)
	}

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

	m, err = LoadMap(path)
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

			if ok, err := outer.Get(uint32(0), inner); err != nil {
				t.Fatal(err)
			} else if !ok {
				t.Fatal("Missing key 0")
			}

			var v uint32
			if ok, err := inner.Get(uint32(1), &v); err != nil {
				t.Fatal(err, inner)
			} else if !ok {
				t.Fatal("Missing key 0")
			}

			if v != 4242 {
				t.Error("Expected value 4242, got", v)
			}
		})
	}
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

	fmt.Println("First key is", firstKey)

	var nextKey string
	if ok, err := hash.NextKey(firstKey, &nextKey); err != nil {
		panic(err)
	} else if !ok {
		panic("no keys after " + firstKey)
	}

	fmt.Println("Next key is", nextKey)

	// Output: First key is world
	// Next key is hello
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

	// Create a new iterator. You can create multiple iterators
	// without them affecting each other.
	entries := hash.Iterate()

	var key string
	var value uint32

	// Important: you must use pointers here if you do not
	// have a custom marshaler implementation.
	for entries.Next(&key, &value) {
		fmt.Printf("key: %s, value: %d\n", key, value)
	}

	if err := entries.Err(); err != nil {
		fmt.Println("Iterator encountered an error:", err)
	}

	// Output: key: world, value: 42
	// key: hello, value: 21
}
