package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/sysenc"
)

// VariableSpec is a convenience wrapper for modifying global variables of a
// CollectionSpec before loading it into the kernel.
//
// All operations on a VariableSpec's underlying MapSpec are performed in the
// host's native endianness.
type VariableSpec struct {
	name   string
	offset uint64
	size   uint64

	m *MapSpec
	t btf.Type
}

// Set sets the value of the VariableSpec to the provided input using the host's
// native endianness.
func (s *VariableSpec) Set(in any) error {
	buf, err := sysenc.Marshal(in, int(s.size))
	if err != nil {
		return fmt.Errorf("marshaling value %s: %w", s.name, err)
	}

	b, _, err := s.m.dataSection()
	if err != nil {
		return fmt.Errorf("getting data section of map %s: %w", s.m.Name, err)
	}

	if int(s.offset+s.size) > len(b) {
		return fmt.Errorf("offset %d(+%d) for variable %s is out of bounds", s.offset, s.size, s.name)
	}

	// MapSpec.Copy() performs a shallow copy. Fully copy the byte slice
	// to avoid any changes affecting other copies of the MapSpec.
	cpy := make([]byte, len(b))
	copy(cpy, b)

	buf.CopyTo(cpy[s.offset : s.offset+s.size])

	s.m.Contents[0] = MapKV{Key: uint32(0), Value: cpy}

	return nil
}

// Get writes the value of the VariableSpec to the provided output using the
// host's native endianness.
func (s *VariableSpec) Get(out any) error {
	b, _, err := s.m.dataSection()
	if err != nil {
		return fmt.Errorf("getting data section of map %s: %w", s.m.Name, err)
	}

	if int(s.offset+s.size) > len(b) {
		return fmt.Errorf("offset %d(+%d) for variable %s is out of bounds", s.offset, s.size, s.name)
	}

	if err := sysenc.Unmarshal(out, b[s.offset:s.offset+s.size]); err != nil {
		return fmt.Errorf("unmarshaling value: %w", err)
	}

	return nil
}

// Size returns the size of the variable in bytes.
func (s *VariableSpec) Size() uint64 {
	return s.size
}

// Constant returns true if the VariableSpec represents a variable that is
// read-only from the perspective of the BPF program.
func (s *VariableSpec) Constant() bool {
	return s.m.readOnly()
}

// Type returns the BTF Type of the variable.
func (s *VariableSpec) Type() btf.Type {
	return s.t
}

func (s *VariableSpec) String() string {
	return fmt.Sprintf("%s (type=%v, map=%s, offset=%d, size=%d)", s.name, s.t, s.m.Name, s.offset, s.size)
}

// copy returns a new VariableSpec with the same values as the original,
// but with a different underlying MapSpec. This is useful when copying a
// CollectionSpec. Returns nil if a MapSpec with the same name is not found.
func (s *VariableSpec) copy(cpy *CollectionSpec) *VariableSpec {
	out := &VariableSpec{
		name:   s.name,
		offset: s.offset,
		size:   s.size,
		t:      s.t,
	}

	// Attempt to find a MapSpec with the same name in the copied CollectionSpec.
	for _, m := range cpy.Maps {
		if m.Name == s.m.Name {
			out.m = m
			return out
		}
	}

	return nil
}
