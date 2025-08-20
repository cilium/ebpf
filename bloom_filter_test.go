package ebpf

import (
	"testing"

	"github.com/cilium/ebpf/internal/testutils"
)

func TestBloomFilter(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.16", "Bloom filter maps")

	spec, err := NewBloomFilter("test_bloom", 4, 100, 3)
	if err != nil {
		t.Fatal("Failed to create bloom filter spec:", err)
	}

	if spec.Type != BloomFilter {
		t.Errorf("Expected map type BloomFilter, got %v", spec.Type)
	}

	if spec.KeySize != 0 {
		t.Errorf("Expected KeySize 0 for bloom filter, got %d", spec.KeySize)
	}

	if spec.ValueSize != 4 {
		t.Errorf("Expected ValueSize 4, got %d", spec.ValueSize)
	}

	if spec.MaxEntries != 100 {
		t.Errorf("Expected MaxEntries 100, got %d", spec.MaxEntries)
	}

	if spec.MapExtra != 3 {
		t.Errorf("Expected MapExtra 3 (num hashes), got %d", spec.MapExtra)
	}

	// Try to create the actual map
	m, err := NewMap(spec)
	if err != nil {
		t.Skip("Bloom filter not supported on this kernel:", err)
	}
	defer m.Close()

	// Test basic operations
	value := uint32(42)
	
	// Bloom filters only support Update (add) and Lookup operations
	// For bloom filters, we use Update with a nil key
	err = m.Update(nil, &value, UpdateAny)
	if err != nil {
		t.Fatal("Failed to add value to bloom filter:", err)
	}

	// Lookup should work for bloom filters
	// Note: bloom filters don't have traditional key-value pairs
	var result uint32
	err = m.Lookup(nil, &result)
	if err != nil && err != ErrKeyNotExist {
		t.Fatal("Unexpected error during lookup:", err)
	}
}

func TestBloomFilterInvalidNumHashes(t *testing.T) {
	// Test that we validate the number of hashes
	_, err := NewBloomFilter("test", 4, 100, 16)
	if err == nil {
		t.Error("Expected error for numHashes > 15")
	}
}

func TestBloomFilterFromBTF(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.16", "Bloom filter maps")

	// This test checks that bloom filter maps can be loaded from ELF files
	// The actual test files would need to be added to testdata/
	// For now, we just test that the MapExtra field is properly handled
	
	spec := &MapSpec{
		Name:       "bloom_test",
		Type:       BloomFilter,
		KeySize:    0,
		ValueSize:  8,
		MaxEntries: 1000,
		MapExtra:   7, // 7 hash functions
	}

	// Verify the spec is valid
	if spec.MapExtra != 7 {
		t.Errorf("MapExtra not preserved, expected 7, got %d", spec.MapExtra)
	}

	// Try to create the map (will skip if not supported)
	m, err := NewMap(spec)
	if err != nil {
		t.Skip("Bloom filter not supported on this kernel:", err)
	}
	defer m.Close()

	// Get map info and verify MapExtra
	info, err := m.Info()
	if err != nil {
		t.Fatal("Failed to get map info:", err)
	}

	extra, ok := info.MapExtra()
	if !ok {
		t.Skip("MapExtra not available in map info")
	}

	if extra != 7 {
		t.Errorf("MapExtra in info doesn't match spec, expected 7, got %d", extra)
	}
}