package ebpf

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

// ErrNotExist is returned when loading a non-existing map or program.
//
// Deprecated: use os.ErrNotExist instead.
var ErrNotExist = os.ErrNotExist

// RemoveMemlockRlimit removes the limit on the amount of memory the current
// process can lock into RAM. Returns a function that restores the limit to
// its previous value.
//
// This is not required to load eBPF resources on kernel versions 5.11+
// due to the introduction of cgroup-based memory accounting.
func RemoveMemlockRlimit() (func() error, error) {
	return unix.RemoveMemlockRlimit()
}

// invalidBPFObjNameChar returns true if char may not appear in
// a BPF object name.
func invalidBPFObjNameChar(char rune) bool {
	dotAllowed := objNameAllowsDot() == nil

	switch {
	case char >= 'A' && char <= 'Z':
		return false
	case char >= 'a' && char <= 'z':
		return false
	case char >= '0' && char <= '9':
		return false
	case dotAllowed && char == '.':
		return false
	case char == '_':
		return false
	default:
		return true
	}
}

func bpfProgTestRun(attr *sys.ProgRunAttr) error {
	_, err := sys.BPF(sys.BPF_PROG_TEST_RUN, unsafe.Pointer(attr), unsafe.Sizeof(*attr))
	return err
}

var haveNestedMaps = internal.FeatureTest("nested maps", "4.12", func() error {
	_, err := sys.MapCreate(&sys.MapCreateAttr{
		MapType:    sys.MapType(ArrayOfMaps),
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		// Invalid file descriptor.
		InnerMapFd: ^uint32(0),
	})
	if errors.Is(err, unix.EINVAL) {
		return internal.ErrNotSupported
	}
	if errors.Is(err, unix.EBADF) {
		return nil
	}
	return err
})

var haveMapMutabilityModifiers = internal.FeatureTest("read- and write-only maps", "5.2", func() error {
	// This checks BPF_F_RDONLY_PROG and BPF_F_WRONLY_PROG. Since
	// BPF_MAP_FREEZE appeared in 5.2 as well we don't do a separate check.
	m, err := sys.MapCreate(&sys.MapCreateAttr{
		MapType:    sys.MapType(Array),
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		MapFlags:   unix.BPF_F_RDONLY_PROG,
	})
	if err != nil {
		return internal.ErrNotSupported
	}
	_ = m.Close()
	return nil
})

var haveMmapableMaps = internal.FeatureTest("mmapable maps", "5.5", func() error {
	// This checks BPF_F_MMAPABLE, which appeared in 5.5 for array maps.
	m, err := sys.MapCreate(&sys.MapCreateAttr{
		MapType:    sys.MapType(Array),
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		MapFlags:   unix.BPF_F_MMAPABLE,
	})
	if err != nil {
		return internal.ErrNotSupported
	}
	_ = m.Close()
	return nil
})

var haveInnerMaps = internal.FeatureTest("inner maps", "5.10", func() error {
	// This checks BPF_F_INNER_MAP, which appeared in 5.10.
	m, err := sys.MapCreate(&sys.MapCreateAttr{
		MapType:    sys.MapType(Array),
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		MapFlags:   unix.BPF_F_INNER_MAP,
	})
	if err != nil {
		return internal.ErrNotSupported
	}
	_ = m.Close()
	return nil
})

func bpfMapLookupElem(m *sys.FD, key, valueOut sys.Pointer) error {
	attr := sys.MapLookupElemAttr{
		MapFd: m.Uint(),
		Key:   key,
		Value: valueOut,
	}
	_, err := sys.BPF(sys.BPF_MAP_LOOKUP_ELEM, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return wrapMapError(err)
}

func bpfMapLookupAndDelete(m *sys.FD, key, valueOut sys.Pointer) error {
	attr := sys.MapLookupAndDeleteElemAttr{
		MapFd: m.Uint(),
		Key:   key,
		Value: valueOut,
	}
	_, err := sys.BPF(sys.BPF_MAP_LOOKUP_AND_DELETE_ELEM, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return wrapMapError(err)
}

func bpfMapUpdateElem(m *sys.FD, key, valueOut sys.Pointer, flags uint64) error {
	attr := sys.MapUpdateElemAttr{
		MapFd: m.Uint(),
		Key:   key,
		Value: valueOut,
		Flags: flags,
	}
	_, err := sys.BPF(sys.BPF_MAP_UPDATE_ELEM, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return wrapMapError(err)
}

func bpfMapDeleteElem(m *sys.FD, key sys.Pointer) error {
	attr := sys.MapDeleteElemAttr{
		MapFd: m.Uint(),
		Key:   key,
	}
	_, err := sys.BPF(sys.BPF_MAP_DELETE_ELEM, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return wrapMapError(err)
}

func bpfMapGetNextKey(m *sys.FD, key, nextKeyOut sys.Pointer) error {
	attr := sys.MapGetNextKeyAttr{
		MapFd:   m.Uint(),
		Key:     key,
		NextKey: nextKeyOut,
	}
	_, err := sys.BPF(sys.BPF_MAP_GET_NEXT_KEY, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return wrapMapError(err)
}

func objGetNextID(cmd sys.Cmd, start uint32) (uint32, error) {
	attr := sys.MapGetNextIdAttr{
		Id: start,
	}
	_, err := sys.BPF(cmd, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return attr.NextId, err
}

func bpfMapBatch(cmd sys.Cmd, m *sys.FD, inBatch, outBatch, keys, values sys.Pointer, count uint32, opts *BatchOptions) (uint32, error) {
	attr := sys.MapLookupBatchAttr{
		InBatch:  inBatch,
		OutBatch: outBatch,
		Keys:     keys,
		Values:   values,
		Count:    count,
		MapFd:    m.Uint(),
	}
	if opts != nil {
		attr.ElemFlags = opts.ElemFlags
		attr.Flags = opts.Flags
	}
	_, err := sys.BPF(cmd, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	// always return count even on an error, as things like update might partially be fulfilled.
	return attr.Count, wrapMapError(err)
}

func wrapMapError(err error) error {
	if err == nil {
		return nil
	}

	if errors.Is(err, unix.ENOENT) {
		return sys.Error(ErrKeyNotExist, unix.ENOENT)
	}

	if errors.Is(err, unix.EEXIST) {
		return sys.Error(ErrKeyExist, unix.EEXIST)
	}

	if errors.Is(err, unix.ENOTSUPP) {
		return sys.Error(ErrNotSupported, unix.ENOTSUPP)
	}

	if errors.Is(err, unix.E2BIG) {
		return fmt.Errorf("key too big for map: %w", err)
	}

	return err
}

func bpfMapFreeze(m *sys.FD) error {
	attr := sys.MapFreezeAttr{
		MapFd: m.Uint(),
	}
	_, err := sys.BPF(sys.BPF_MAP_FREEZE, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return err
}

func bpfGetProgInfoByFD(fd *sys.FD, ids []MapID) (*sys.ProgInfo, error) {
	var info sys.ProgInfo
	if len(ids) > 0 {
		info.NrMapIds = uint32(len(ids))
		info.MapIds = sys.NewPointer(unsafe.Pointer(&ids[0]))
	}

	if err := sys.ObjGetInfoByFD(fd, unsafe.Pointer(&info), unsafe.Sizeof(info)); err != nil {
		return nil, fmt.Errorf("can't get program info: %w", err)
	}
	return &info, nil
}

func bpfGetMapInfoByFD(fd *sys.FD) (*sys.MapInfo, error) {
	var info sys.MapInfo
	err := sys.ObjGetInfoByFD(fd, unsafe.Pointer(&info), unsafe.Sizeof(info))
	if err != nil {
		return nil, fmt.Errorf("can't get map info: %w", err)
	}
	return &info, nil
}

var haveObjName = internal.FeatureTest("object names", "4.15", func() error {
	attr := sys.MapCreateAttr{
		MapType:    sys.MapType(Array),
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		MapName:    sys.NewObjName("feature_test"),
	}

	fd, err := sys.MapCreate(&attr)
	if err != nil {
		return internal.ErrNotSupported
	}

	_ = fd.Close()
	return nil
})

var objNameAllowsDot = internal.FeatureTest("dot in object names", "5.2", func() error {
	if err := haveObjName(); err != nil {
		return err
	}

	attr := sys.MapCreateAttr{
		MapType:    sys.MapType(Array),
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		MapName:    sys.NewObjName(".test"),
	}

	fd, err := sys.MapCreate(&attr)
	if err != nil {
		return internal.ErrNotSupported
	}

	_ = fd.Close()
	return nil
})

var haveBatchAPI = internal.FeatureTest("map batch api", "5.6", func() error {
	var maxEntries uint32 = 2
	attr := sys.MapCreateAttr{
		MapType:    sys.MapType(Hash),
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: maxEntries,
	}

	fd, err := sys.MapCreate(&attr)
	if err != nil {
		return internal.ErrNotSupported
	}
	defer fd.Close()
	keys := []uint32{1, 2}
	values := []uint32{3, 4}
	kp, _ := marshalPtr(keys, 8)
	vp, _ := marshalPtr(values, 8)
	nilPtr := sys.NewPointer(nil)
	_, err = bpfMapBatch(sys.BPF_MAP_UPDATE_BATCH, fd, nilPtr, nilPtr, kp, vp, maxEntries, nil)
	if err != nil {
		return internal.ErrNotSupported
	}
	return nil
})

var haveProbeReadKernel = internal.FeatureTest("bpf_probe_read_kernel", "5.5", func() error {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R1, asm.R10),
		asm.Add.Imm(asm.R1, -8),
		asm.Mov.Imm(asm.R2, 8),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnProbeReadKernel.Call(),
		asm.Return(),
	}
	buf := bytes.NewBuffer(make([]byte, 0, len(insns)*asm.InstructionSize))
	if err := insns.Marshal(buf, internal.NativeEndian); err != nil {
		return err
	}
	bytecode := buf.Bytes()

	fd, err := sys.ProgLoad(&sys.ProgLoadAttr{
		ProgType: sys.ProgType(Kprobe),
		License:  sys.NewStringPointer("GPL"),
		Insns:    sys.NewSlicePointer(bytecode),
		InsnCnt:  uint32(len(bytecode) / asm.InstructionSize),
	})
	if err != nil {
		return internal.ErrNotSupported
	}
	_ = fd.Close()
	return nil
})
