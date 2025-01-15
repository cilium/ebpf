package features

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/linux"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/sysenc"
	"github.com/cilium/ebpf/internal/tracefs"
	"github.com/cilium/ebpf/internal/unix"
)

func progLoad(insns asm.Instructions, typ sys.ProgType, license string) (*sys.FD, error) {
	buf := bytes.NewBuffer(make([]byte, 0, insns.Size()))
	if err := insns.Marshal(buf, internal.NativeEndian); err != nil {
		return nil, err
	}
	bytecode := buf.Bytes()

	return sys.ProgLoad(&sys.ProgLoadAttr{
		ProgType: typ,
		License:  sys.NewStringPointer(license),
		Insns:    sys.NewSlicePointer(bytecode),
		InsnCnt:  uint32(len(bytecode) / asm.InstructionSize),
	})
}

var haveNestedMaps = internal.NewFeatureTest("nested maps", func() error {
	_, err := sys.MapCreate(&sys.MapCreateAttr{
		MapType:    sys.BPF_MAP_TYPE_ARRAY_OF_MAPS,
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
}, "4.12")

// HaveNestedMaps returns a nil error if nested maps are supported.
func HaveNestedMaps() error {
	return haveNestedMaps()
}

var haveMapMutabilityModifiers = internal.NewFeatureTest("read- and write-only maps", func() error {
	// This checks BPF_F_RDONLY_PROG and BPF_F_WRONLY_PROG. Since
	// BPF_MAP_FREEZE appeared in 5.2 as well we don't do a separate check.
	m, err := sys.MapCreate(&sys.MapCreateAttr{
		MapType:    sys.BPF_MAP_TYPE_ARRAY,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		MapFlags:   sys.BPF_F_RDONLY_PROG,
	})
	if err != nil {
		return internal.ErrNotSupported
	}
	_ = m.Close()
	return nil
}, "5.2")

// HaveMapMutabilityModifiers returns a nil error if map
// mutability modifiers are supported.
func HaveMapMutabilityModifiers() error {
	return haveMapMutabilityModifiers()
}

var haveMmapableMaps = internal.NewFeatureTest("mmapable maps", func() error {
	// This checks BPF_F_MMAPABLE, which appeared in 5.5 for array maps.
	m, err := sys.MapCreate(&sys.MapCreateAttr{
		MapType:    sys.BPF_MAP_TYPE_ARRAY,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		MapFlags:   sys.BPF_F_MMAPABLE,
	})
	if err != nil {
		return internal.ErrNotSupported
	}
	_ = m.Close()
	return nil
}, "5.5")

// HaveMmapableMaps returns a nil error if mmapable maps
// are supported.
func HaveMmapableMaps() error {
	return haveMmapableMaps()
}

var haveInnerMaps = internal.NewFeatureTest("inner maps", func() error {
	// This checks BPF_F_INNER_MAP, which appeared in 5.10.
	m, err := sys.MapCreate(&sys.MapCreateAttr{
		MapType:    sys.BPF_MAP_TYPE_ARRAY,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		MapFlags:   sys.BPF_F_INNER_MAP,
	})

	if err != nil {
		return internal.ErrNotSupported
	}
	_ = m.Close()
	return nil
}, "5.10")

// HaveInnerMaps returns a nil error if inner maps are supported.
func HaveInnerMaps() error {
	return haveInnerMaps()
}

var haveNoPreallocMaps = internal.NewFeatureTest("prealloc maps", func() error {
	// This checks BPF_F_NO_PREALLOC, which appeared in 4.6.
	m, err := sys.MapCreate(&sys.MapCreateAttr{
		MapType:    sys.BPF_MAP_TYPE_HASH,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		MapFlags:   sys.BPF_F_NO_PREALLOC,
	})

	if err != nil {
		return internal.ErrNotSupported
	}
	_ = m.Close()
	return nil
}, "4.6")

// HaveNoPreallocMaps returns a nil error if the flag for
// creating maps that are not pre-allocated is supported.
func HaveNoPreallocMaps() error {
	return haveNoPreallocMaps()
}

var haveObjName = internal.NewFeatureTest("object names", func() error {
	attr := sys.MapCreateAttr{
		MapType:    sys.BPF_MAP_TYPE_ARRAY,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		MapName:    sys.NewObjName("feature_test"),
	}

	// Tolerate EPERM as this runs during ELF loading which is potentially
	// unprivileged. Only EINVAL is conclusive, thrown from CHECK_ATTR.
	fd, err := sys.MapCreate(&attr)
	if errors.Is(err, unix.EPERM) {
		return nil
	}
	if errors.Is(err, unix.EINVAL) {
		return internal.ErrNotSupported
	}
	if err != nil {
		return err
	}

	_ = fd.Close()
	return nil
}, "4.15")

// HaveObjName returns a nil error if object names are supported
func HaveObjName() error {
	return haveObjName()
}

var objNameAllowsDot = internal.NewFeatureTest("dot in object names", func() error {
	if err := haveObjName(); err != nil {
		return err
	}

	attr := sys.MapCreateAttr{
		MapType:    sys.BPF_MAP_TYPE_ARRAY,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
		MapName:    sys.NewObjName(".test"),
	}

	// Tolerate EPERM, otherwise MapSpec.Name has its dots removed when run by
	// unprivileged tools. (bpf2go, other code gen). Only EINVAL is conclusive,
	// thrown from bpf_obj_name_cpy().
	fd, err := sys.MapCreate(&attr)
	if errors.Is(err, unix.EPERM) {
		return nil
	}
	if errors.Is(err, unix.EINVAL) {
		return internal.ErrNotSupported
	}
	if err != nil {
		return err
	}

	_ = fd.Close()
	return nil
}, "5.2")

// ObjNameAllowsDot returns a nil error if object names support
// the dot character, i.e. ".".
func ObjNameAllowsDot() error {
	return objNameAllowsDot()
}

func marshalMapSyscallInput(data any, length int) (sys.Pointer, error) {
	if ptr, ok := data.(unsafe.Pointer); ok {
		return sys.NewPointer(ptr), nil
	}

	buf, err := sysenc.Marshal(data, length)
	if err != nil {
		return sys.Pointer{}, err
	}

	return buf.Pointer(), nil
}

var haveBatchAPI = internal.NewFeatureTest("map batch api", func() error {
	var maxEntries uint32 = 2
	attr := sys.MapCreateAttr{
		MapType:    sys.BPF_MAP_TYPE_HASH,
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
	kp, _ := marshalMapSyscallInput(keys, 8)
	vp, _ := marshalMapSyscallInput(values, 8)

	err = sys.MapUpdateBatch(&sys.MapUpdateBatchAttr{
		MapFd:  fd.Uint(),
		Keys:   kp,
		Values: vp,
		Count:  maxEntries,
	})
	if err != nil {
		return internal.ErrNotSupported
	}
	return nil
}, "5.6")

// HaveBatchAPI returns a nil error if batch operations are supported
func HaveBatchAPI() error {
	return haveBatchAPI()
}

var haveProbeReadKernel = internal.NewFeatureTest("bpf_probe_read_kernel", func() error {
	insns := asm.Instructions{
		asm.Mov.Reg(asm.R1, asm.R10),
		asm.Add.Imm(asm.R1, -8),
		asm.Mov.Imm(asm.R2, 8),
		asm.Mov.Imm(asm.R3, 0),
		asm.FnProbeReadKernel.Call(),
		asm.Return(),
	}

	fd, err := progLoad(insns, sys.BPF_PROG_TYPE_KPROBE, "GPL")
	if err != nil {
		return internal.ErrNotSupported
	}
	_ = fd.Close()
	return nil
}, "5.5")

// HaveProbeReadKernel returns a nil error if kprobes are supported.
func HaveProbeReadKernel() error {
	return haveProbeReadKernel()
}

var haveBPFToBPFCalls = internal.NewFeatureTest("bpf2bpf calls", func() error {
	insns := asm.Instructions{
		asm.Call.Label("prog2").WithSymbol("prog1"),
		asm.Return(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("prog2"),
		asm.Return(),
	}

	fd, err := progLoad(insns, sys.BPF_PROG_TYPE_SOCKET_FILTER, "MIT")
	if err != nil {
		return internal.ErrNotSupported
	}
	_ = fd.Close()
	return nil
}, "4.16")

// HaveBPFToBPFCalls returns a nil error if bpf programs can call other bpf
// programs.
func HaveBPFToBPFCalls() error {
	return haveBPFToBPFCalls()
}

var haveSyscallWrapper = internal.NewFeatureTest("syscall wrapper", func() error {
	prefix := linux.PlatformPrefix()
	if prefix == "" {
		return fmt.Errorf("unable to find the platform prefix for (%s)", runtime.GOARCH)
	}

	args := tracefs.ProbeArgs{
		Type:   tracefs.Kprobe,
		Symbol: prefix + "sys_bpf",
		Pid:    -1,
	}

	var err error
	args.Group, err = tracefs.RandomGroup("ebpf_probe")
	if err != nil {
		return err
	}

	evt, err := tracefs.NewEvent(args)
	if errors.Is(err, os.ErrNotExist) {
		return internal.ErrNotSupported
	}
	if err != nil {
		return err
	}

	return evt.Close()
}, "4.17")

// HaveSyscallWrapper returns a nil error if syscall wrapper is not supported.
func HaveSyscallWrapper() error {
	return haveSyscallWrapper()
}

var haveProgramExtInfos = internal.NewFeatureTest("program ext_infos", func() error {
	insns := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	buf := bytes.NewBuffer(make([]byte, 0, insns.Size()))
	if err := insns.Marshal(buf, internal.NativeEndian); err != nil {
		return err
	}
	bytecode := buf.Bytes()

	_, err := sys.ProgLoad(&sys.ProgLoadAttr{
		ProgType:    sys.BPF_PROG_TYPE_SOCKET_FILTER,
		License:     sys.NewStringPointer("MIT"),
		Insns:       sys.NewSlicePointer(bytecode),
		InsnCnt:     uint32(len(bytecode) / asm.InstructionSize),
		FuncInfoCnt: 1,
		ProgBtfFd:   math.MaxUint32,
	})

	if errors.Is(err, unix.EBADF) {
		return nil
	}

	if errors.Is(err, unix.E2BIG) {
		return internal.ErrNotSupported
	}

	return err
}, "5.0")

// HaveProgramExtInfos returns a nil error if program BTF is supported
func HaveProgramExtInfos() error {
	return haveProgramExtInfos()
}

var haveProgramInfoMapIDs = internal.NewFeatureTest("map IDs in program info", func() error {
	prog, err := progLoad(asm.Instructions{
		asm.LoadImm(asm.R0, 0, asm.DWord),
		asm.Return(),
	}, sys.BPF_PROG_TYPE_SOCKET_FILTER, "MIT")
	if err != nil {
		return err
	}
	defer prog.Close()

	err = sys.ObjInfo(prog, &sys.ProgInfo{
		// NB: Don't need to allocate MapIds since the program isn't using
		// any maps.
		NrMapIds: 1,
	})
	if errors.Is(err, unix.EINVAL) {
		// Most likely the syscall doesn't exist.
		return internal.ErrNotSupported
	}
	if errors.Is(err, unix.E2BIG) {
		// We've hit check_uarg_tail_zero on older kernels.
		return internal.ErrNotSupported
	}

	return err
}, "4.15")

// HaveProgramInfoMapIDs returns a nil error if retrieving map ids from
// program's object info is supported.
func HaveProgramInfoMapIDs() error {
	return haveProgramInfoMapIDs()
}

var haveProgRun = internal.NewFeatureTest("BPF_PROG_RUN", func() error {
	prog, err := progLoad(asm.Instructions{
		asm.LoadImm(asm.R0, 0, asm.DWord),
		asm.Return(),
	}, sys.BPF_PROG_TYPE_SOCKET_FILTER, "MIT")
	if err != nil {
		// This may be because we lack sufficient permissions, etc.
		return err
	}
	defer prog.Close()

	in := internal.EmptyBPFContext
	attr := sys.ProgRunAttr{
		ProgFd:     uint32(prog.Int()),
		DataSizeIn: uint32(len(in)),
		DataIn:     sys.NewSlicePointer(in),
	}

	err = sys.ProgRun(&attr)
	switch {
	case errors.Is(err, unix.EINVAL):
		// Check for EINVAL specifically, rather than err != nil since we
		// otherwise misdetect due to insufficient permissions.
		return internal.ErrNotSupported

	case errors.Is(err, unix.EINTR):
		// We know that PROG_TEST_RUN is supported if we get EINTR.
		return nil

	case errors.Is(err, sys.ENOTSUPP):
		// The first PROG_TEST_RUN patches shipped in 4.12 didn't include
		// a test runner for SocketFilter. ENOTSUPP means PROG_TEST_RUN is
		// supported, but not for the program type used in the probe.
		return nil
	}

	return err
}, "4.12")

// HaveProgTestRun returns a nil error if the bpf command
// PROG_TEST_RUN is supported.
func HaveProgTestRun() error {
	return haveProgRun()
}
