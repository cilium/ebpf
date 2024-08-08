package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"reflect"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/unix"
)

// VariableOptions control loading the variables into the kernel.
// TODO: Usage?
type VariableOptions struct{}

// VariableSpec defines a Variable.
type VariableSpec struct {
	Name    string
	MapName string
	Offset  uint64
	Size    uint64
}

// Copy returns a deep copy of the spec.
func (ss *VariableSpec) Copy() *VariableSpec {
	if ss == nil {
		return nil
	}

	return &VariableSpec{
		Name:    ss.Name,
		MapName: ss.MapName,
		Offset:  ss.Offset,
		Size:    ss.Size,
	}
}

// Variable represents a variable in the ebpf program (static/global variables).
//
// It is not safe to close a variable which is used by other goroutines.
//
// Methods which take interface{} arguments by default encode
// them using binary.Read/Write in the machine's native endianness.
type Variable struct {
	name   string
	offset uint64
	size   uint64
	m      *Map
	mmaped []byte
}

// Size returns the size of the variable.
func (v *Variable) Size() uint64 {
	return v.size
}

// newVariableWithOptions creates a new variable with the needed mmap-ed data referencing
// the underlying portion of the map, if supported.
func newVariableWithOptions(spec *VariableSpec, m *Map, opts VariableOptions) (*Variable, error) {
	return &Variable{
		name:   spec.Name,
		offset: spec.Offset,
		size:   spec.Size,
		m:      m,
		mmaped: nil}, nil
}

// writeMmapBuf uses a `bytes.Buffer` to write the provided variable into the mmap-ed data.
func (v *Variable) writeMmapBuf(value interface{}) error {
	var buf bytes.Buffer
	if err := binary.Write(&buf, internal.NativeEndian, value); err != nil {
		return err
	}

	copy(v.mmaped[v.offset:v.offset+v.size], buf.Bytes())
	return nil
}

// readMmapBuf uses a `bytes.Reader` to read from the mmap-ed data into the provided variable.
func (v *Variable) readMmapBuf(value interface{}) error {
	buf := bytes.NewReader(v.mmaped[v.offset : v.offset+v.size])
	return binary.Read(buf, internal.NativeEndian, value)
}

// writeLookup implements the sequential `Map.Lookup` and `Map.Update` to
// retrieve and update the variable value.
func (v *Variable) writeLookup(value interface{}) error {
	var buf bytes.Buffer
	if err := binary.Write(&buf, internal.NativeEndian, value); err != nil {
		return err
	}

	var k int32
	data := make([]byte, v.m.valueSize)

	if err := v.m.Lookup(&k, data); err != nil {
		return err
	}

	copy(data[v.offset:v.offset+v.size], buf.Bytes())
	return v.m.Update(k, data, UpdateExist)
}

// readLookup uses `Map.Lookup` to retrieve the variable value.
func (v *Variable) readLookup(value interface{}) error {
	var k int32
	data := make([]byte, v.m.valueSize)
	if err := v.m.Lookup(&k, data); err != nil {
		return err
	}

	buf := bytes.NewReader(data[v.offset : v.offset+v.size])
	return binary.Read(buf, internal.NativeEndian, value)
}

// Store changes the variable value. This operation is performed atomically when
// the variable is mmap-ed and the provided argument is one of the following types:
// uint32, *uint32, int32, *int32, uint64, *uint64, int64, *int64, uintptr, *uintptr, unsafe.Pointer.
// For all the other types, it uses the non-atomic byte buffer read-write method when mmap-ed,
// otherwise it uses `Map.Lookup` and `Map.Update`.
func (v *Variable) Store(value interface{}) error {
	if !v.isMmaped() {
		if err := v.writeLookup(value); err != nil {
			return fmt.Errorf("failed to store value through map lookup and update: %w", err)
		}
	}

	// TODO: ensure sizeof value == v.mmaped

	switch vv := value.(type) {
	case uint32:
		atomic.StoreUint32((*uint32)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])), vv)
	case *uint32:
		atomic.StoreUint32((*uint32)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])), *vv)
	case int32:
		atomic.StoreInt32((*int32)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])), vv)
	case *int32:
		atomic.StoreInt32((*int32)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])), *vv)
	case uint64:
		atomic.StoreUint64((*uint64)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])), vv)
	case *uint64:
		atomic.StoreUint64((*uint64)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])), *vv)
	case int64:
		atomic.StoreInt64((*int64)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])), vv)
	case *int64:
		atomic.StoreInt64((*int64)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])), *vv)
	case uintptr:
		atomic.StoreUintptr((*uintptr)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])), vv)
	case *uintptr:
		atomic.StoreUintptr((*uintptr)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])), *vv)
	case unsafe.Pointer:
		atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])), vv)
	case *unsafe.Pointer:
		atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&v.mmaped[0])), *vv)
	default:
		if err := v.writeMmapBuf(value); err != nil {
			return fmt.Errorf("failed to store value through mmap byte buffer: %w", err)
		}
	}

	return nil
}

// Load retrieves the variable value. This operation is performed atomically when
// the variable is retrieved through the traditional `Map.Lookup`, or when the variable is
// mmap-ed and the provided argument is one of the following types: uint32, *uint32, int32,
// *int32, uint64, *uint64, int64, *int64, uintptr, *uintptr, unsafe.Pointer.
// For all the other types, it uses the non-atomic byte buffer read-write method.
func (v *Variable) Load(value interface{}) error {
	if reflect.ValueOf(value).Kind() != reflect.Ptr {
		return fmt.Errorf("must provide a pointer")
	}

	if !v.isMmaped() {
		if err := v.readLookup(value); err != nil {
			return fmt.Errorf("failed to load value through map lookup: %w", err)
		}
		return nil
	}

	// TODO: ensure sizeof value == v.mmaped

	switch vv := value.(type) {
	case *uint32:
		*vv = atomic.LoadUint32((*uint32)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])))
	case *int32:
		*vv = atomic.LoadInt32((*int32)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])))
	case *uint64:
		*vv = atomic.LoadUint64((*uint64)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])))
	case *int64:
		*vv = atomic.LoadInt64((*int64)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])))
	case *uintptr:
		*vv = atomic.LoadUintptr((*uintptr)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])))
	case *unsafe.Pointer:
		*vv = atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&v.mmaped[v.offset : v.offset+v.size][0])))
	default:
		if err := v.readMmapBuf(value); err != nil {
			return fmt.Errorf("failed to load value through mmap byte buffer: %w", err)
		}
	}

	return nil
}

func (v *Variable) isMmaped() bool {
	return v.mmaped != nil && len(v.mmaped) > 0
}

func (v *Variable) Mmap() error {
	if v.isMmaped() {
		return nil
	}

	if v.m.flags&unix.BPF_F_MMAPABLE == 0 || haveMmapableMaps() != nil {
		return nil
	}

	proto := syscall.PROT_WRITE
	if v.m.flags&unix.BPF_F_RDONLY_PROG == 0 {
		proto = syscall.PROT_WRITE
	}
	data, err := syscall.Mmap(v.m.FD(), 0, v.m.fullValueSize*int(v.m.maxEntries), proto, syscall.MAP_SHARED)
	if err != nil {
		return fmt.Errorf("failed to mmap map %s: %w", v.m.name, err)
	}

	v.mmaped = data
	return nil
}

// Close performs the variable munmap if it was mmap-ed and closes the respective map.
func (v *Variable) Close() error {
	var err error
	if v.isMmaped() {
		if errMmap := syscall.Munmap(v.mmaped); errMmap != nil {
			err = fmt.Errorf("failed to munmap: %w", errMmap)
		}
	}

	if errClose := v.m.Close(); errClose != nil {
		err = errors.Join(err, fmt.Errorf(". failed to close map: %w", errClose))
	}

	return err
}
