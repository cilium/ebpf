package ebpf

import (
	"fmt"
	"io"
	"reflect"
	"slices"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/sysenc"
)

// VariableSpec is a convenience wrapper for modifying global variables of a
// CollectionSpec before loading it into the kernel.
//
// All operations on a VariableSpec's underlying MapSpec are performed in the
// host's native endianness.
type VariableSpec struct {
	Name string
	// Name of the map this variable belongs to.
	MapName string
	// Offset of the variable within the map.
	Offset int
	// Byte representation of the variables's value.
	Value []byte
	// Type information of the variable. Optional.
	Type *btf.Var
}

// Set sets the value of the VariableSpec to the provided input using the host's
// native endianness.
func (s *VariableSpec) Set(in any) error {
	buf, err := sysenc.Marshal(in, len(s.Value))
	if err != nil {
		return fmt.Errorf("marshaling value %s: %w", s.Name, err)
	}

	buf.CopyTo(s.Value)
	return nil
}

// Get writes the value of the VariableSpec to the provided output using the
// host's native endianness.
func (s *VariableSpec) Get(out any) error {
	if err := sysenc.Unmarshal(out, s.Value); err != nil {
		return fmt.Errorf("unmarshaling value: %w", err)
	}

	return nil
}

func (s *VariableSpec) String() string {
	return fmt.Sprintf("%s (type=%v, map=%s)", s.Name, s.Type, s.MapName)
}

// Copy the VariableSpec.
func (s *VariableSpec) Copy() *VariableSpec {
	cpy := *s
	cpy.Value = slices.Clone(s.Value)
	return &cpy
}

// Variable is a convenience wrapper for modifying global variables of a
// Collection after loading it into the kernel. Operations on a Variable are
// performed using direct memory access, bypassing the BPF map syscall API.
//
// On kernels older than 5.5, most interactions with Variable return
// [ErrNotSupported].
type Variable struct {
	name   string
	offset uint64
	size   uint64
	t      *btf.Var

	mm *Memory
}

func newVariable(name string, offset, size int, t *btf.Var, mm *Memory) (*Variable, error) {
	if mm != nil {
		if offset+size > mm.Size() {
			return nil, fmt.Errorf("offset %d(+%d) is out of bounds", offset, size)
		}
	}

	return &Variable{
		name:   name,
		offset: uint64(offset),
		size:   uint64(size),
		t:      t,
		mm:     mm,
	}, nil
}

// Size returns the size of the variable.
func (v *Variable) Size() uint64 {
	return v.size
}

// ReadOnly returns true if the Variable represents a variable that is read-only
// after loading the Collection into the kernel.
//
// On systems without BPF_F_MMAPABLE support, ReadOnly always returns true.
func (v *Variable) ReadOnly() bool {
	if v.mm == nil {
		return true
	}
	return v.mm.ReadOnly()
}

// Type returns the [btf.Var] representing the variable in its data section.
// This is useful for inspecting the variable's decl tags and the type
// information of the inner type.
//
// Returns nil if the original ELF object did not contain BTF information.
func (v *Variable) Type() *btf.Var {
	return v.t
}

func (v *Variable) String() string {
	return fmt.Sprintf("%s (type=%v)", v.name, v.t)
}

// Set the value of the Variable to the provided input. The input must marshal
// to the same length as the size of the Variable.
func (v *Variable) Set(in any) error {
	if v.mm == nil {
		return fmt.Errorf("variable %s: direct access requires Linux 5.5 or later: %w", v.name, ErrNotSupported)
	}

	if v.ReadOnly() {
		return fmt.Errorf("variable %s: %w", v.name, ErrReadOnly)
	}

	if !v.mm.bounds(v.offset, v.size) {
		return fmt.Errorf("variable %s: access out of bounds: %w", v.name, io.EOF)
	}

	buf, err := sysenc.Marshal(in, int(v.size))
	if err != nil {
		return fmt.Errorf("marshaling value %s: %w", v.name, err)
	}

	if _, err := v.mm.WriteAt(buf.Bytes(), int64(v.offset)); err != nil {
		return fmt.Errorf("writing value to %s: %w", v.name, err)
	}

	return nil
}

// Get writes the value of the Variable to the provided output. The output must
// be a pointer to a value whose size matches the Variable.
func (v *Variable) Get(out any) error {
	if v.mm == nil {
		return fmt.Errorf("variable %s: direct access requires Linux 5.5 or later: %w", v.name, ErrNotSupported)
	}

	if !v.mm.bounds(v.offset, v.size) {
		return fmt.Errorf("variable %s: access out of bounds: %w", v.name, io.EOF)
	}

	if err := sysenc.Unmarshal(out, v.mm.b[v.offset:v.offset+v.size]); err != nil {
		return fmt.Errorf("unmarshaling value %s: %w", v.name, err)
	}

	return nil
}

func checkVariable[T any](v *Variable) error {
	if v.ReadOnly() {
		return ErrReadOnly
	}

	t := reflect.TypeFor[T]()
	size := uint64(t.Size())
	if t.Kind() == reflect.Uintptr && v.size == 8 {
		// uintptr is 8 bytes on 64-bit and 4 on 32-bit. In BPF/BTF, pointers are
		// always 8 bytes. For the sake of portability, allow accessing 8-byte BPF
		// variables as uintptr on 32-bit systems, since the upper 32 bits of the
		// pointer should be zero anyway.
		return nil
	}
	if v.size != size {
		return fmt.Errorf("can't create %d-byte accessor to %d-byte variable: %w", size, v.size, ErrInvalidType)
	}

	return nil
}

// VariablePointer returns a pointer to a variable of type T backed by memory
// shared with the BPF program. Requires building the Go application with -tags
// ebpf_unsafe_memory_experiment.
//
// T must contain only fixed-size, non-Go-pointer types: bools, floats,
// (u)int[8-64], arrays, and structs containing them. Structs must embed
// [structs.HostLayout]. [ErrInvalidType] is returned if T is not a valid type.
func VariablePointer[T comparable](v *Variable) (*T, error) {
	if err := checkVariable[T](v); err != nil {
		return nil, fmt.Errorf("variable pointer %s: %w", v.name, err)
	}
	return memoryPointer[T](v.mm, v.offset)
}
