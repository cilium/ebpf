//go:build linux

// maps_main {
package main

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
)

func main() {
	// Each function below is referenced from the documentation. See
	// docs/ebpf/maps for the accompanying text.
	fmt.Println("See docs/ebpf/maps for examples of map operations")
}

// }

// DocMapSpec {
func DocMapSpec() error {
	// maps.o is the object produced by running bpf2go on maps.c. The snippet
	// assumes it sits next to the Go binary.
	spec, err := ebpf.LoadCollectionSpec("maps.o")
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}

	for name, m := range spec.Maps {
		fmt.Printf("%s: %s, key=%d bytes, value=%d bytes, max_entries=%d\n",
			name, m.Type, m.KeySize, m.ValueSize, m.MaxEntries)
	}

	// Look up a specific map by the name of its C variable.
	packets := spec.Maps["packets"]
	fmt.Println(packets.Type)

	return nil
}

// }

// DocNewMap {
func DocNewMap() error {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Name:       "packets",
		Type:       ebpf.Hash,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 1024,
	})
	if err != nil {
		return fmt.Errorf("new map: %w", err)
	}
	// Closing the Map releases the file descriptor. The map itself stays alive
	// for as long as a BPF program, another file descriptor or a pin refers to
	// it.
	defer m.Close()

	return nil
}

// }

// DocMapPutLookup {
func DocMapPutLookup(m *ebpf.Map) error {
	key := uint32(42)
	value := uint64(1)

	// Put creates the entry or overwrites an existing one.
	if err := m.Put(key, value); err != nil {
		return fmt.Errorf("put: %w", err)
	}

	var out uint64
	if err := m.Lookup(key, &out); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("key %d does not exist", key)
		}
		return fmt.Errorf("lookup: %w", err)
	}

	fmt.Println(out)
	return nil
}

// }

// DocMapUpdate {
func DocMapUpdate(m *ebpf.Map) error {
	// Only create the entry if it does not exist yet. Array maps reject this
	// flag, since their elements always exist.
	if err := m.Update(uint32(1), uint64(1), ebpf.UpdateNoExist); err != nil {
		return fmt.Errorf("update: %w", err)
	}

	// Only modify the entry if it already exists.
	if err := m.Update(uint32(1), uint64(2), ebpf.UpdateExist); err != nil {
		return fmt.Errorf("update: %w", err)
	}

	// Delete removes the entry. It returns ErrKeyNotExist if the key is absent.
	if err := m.Delete(uint32(1)); err != nil {
		return fmt.Errorf("delete: %w", err)
	}

	return nil
}

// }

// DocMapIterate {
func DocMapIterate(m *ebpf.Map) error {
	var (
		key   uint32
		value uint64
	)

	iter := m.Iterate()
	for iter.Next(&key, &value) {
		fmt.Println(key, value)
	}

	// Next returns false both when the map is exhausted and when an error
	// occurred, so the iterator must always be checked.
	return iter.Err()
}

// }

// DocMapBatch {
func DocMapBatch(m *ebpf.Map) error {
	keys := make([]uint32, 16)
	values := make([]uint64, 16)

	var cursor ebpf.MapBatchCursor
	n, err := m.BatchLookup(&cursor, keys, values, nil)
	if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("batch lookup: %w", err)
	}
	// ErrKeyNotExist marks the end of the map. n still holds the number of
	// entries written by this call.

	for i := range n {
		fmt.Println(keys[i], values[i])
	}

	return nil
}

// }

// DocMapPerCPU {
func DocMapPerCPU(m *ebpf.Map) error {
	// Per-CPU maps hold one value per possible CPU. Lookups and updates
	// therefore take a slice whose length equals ebpf.MustPossibleCPU().
	values := make([]uint64, ebpf.MustPossibleCPU())

	if err := m.Lookup(uint32(0), values); err != nil {
		return fmt.Errorf("lookup: %w", err)
	}

	for cpu, value := range values {
		fmt.Println(cpu, value)
	}

	return nil
}

// }

// DocMapPin {
func DocMapPin(m *ebpf.Map) error {
	// Pinning keeps the map alive after its file descriptor is closed and makes
	// it reachable by path from other processes.
	if err := m.Pin("/sys/fs/bpf/packets"); err != nil {
		return fmt.Errorf("pin: %w", err)
	}

	pinned, err := ebpf.LoadPinnedMap("/sys/fs/bpf/packets", nil)
	if err != nil {
		return fmt.Errorf("load pinned map: %w", err)
	}
	defer pinned.Close()

	return nil
}

// }

// DocMapStruct {
// flowKey mirrors a struct declared in the eBPF C program. Go and C layouts
// must match byte for byte.
type flowKey struct {
	SrcIP   uint32
	DstIP   uint32
	SrcPort uint16
	DstPort uint16
}

func DocMapStruct() error {
	m, err := ebpf.NewMap(&ebpf.MapSpec{
		Type: ebpf.Hash,
		// binary.Size reports the encoded size, excluding struct padding.
		KeySize:    uint32(binary.Size(flowKey{})),
		ValueSize:  8,
		MaxEntries: 1024,
	})
	if err != nil {
		return fmt.Errorf("new map: %w", err)
	}
	defer m.Close()

	key := flowKey{
		SrcIP:   0x0a000001,
		DstIP:   0x0a000002,
		SrcPort: 1234,
		DstPort: 80,
	}
	if err := m.Put(key, uint64(1)); err != nil {
		return fmt.Errorf("put: %w", err)
	}

	return nil
}

// }
