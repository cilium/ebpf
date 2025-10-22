package ebpf

import (
	"errors"
	"sync"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/testutils"
)

var haveTestmod = sync.OnceValues(func() (bool, error) {
	if platform.IsWindows {
		return false, nil
	}

	// See https://github.com/torvalds/linux/commit/290248a5b7d829871b3ea3c62578613a580a1744
	testmod, err := btf.FindHandle(func(info *btf.HandleInfo) bool {
		return info.IsModule() && info.Name == "bpf_testmod"
	})
	if err != nil && !errors.Is(err, btf.ErrNotFound) {
		return false, err
	}
	testmod.Close()

	return testmod != nil, nil
})

var haveTestmodOps = sync.OnceValues(func() (bool, error) {
	haveTestMod, err := haveTestmod()
	if err != nil {
		return false, err
	}
	if !haveTestMod {
		return false, nil
	}

	target := btf.Type((*btf.Struct)(nil))
	_, module, err := findTargetInKernel("bpf_struct_ops_bpf_testmod_ops", &target, btf.NewCache())
	if err != nil && !errors.Is(err, btf.ErrNotFound) {
		return false, err
	}
	if errors.Is(err, btf.ErrNotFound) {
		return false, nil
	}
	defer module.Close()

	return true, nil
})

func requireTestmod(tb testing.TB) {
	tb.Helper()

	testutils.SkipOnOldKernel(tb, "5.11", "bpf_testmod")

	testmod, err := haveTestmod()
	if err != nil {
		tb.Fatal(err)
	}
	if !testmod {
		tb.Skip("bpf_testmod not loaded")
	}
}

func requireTestmodOps(tb testing.TB) {
	tb.Helper()

	testutils.SkipOnOldKernel(tb, "5.11", "bpf_testmod")
	testmodOps, err := haveTestmodOps()
	if err != nil {
		tb.Fatal(err)
	}
	if !testmodOps {
		tb.Skip("bpf_testmod_ops not loaded")
	}
}

func newMap(tb testing.TB, spec *MapSpec, opts *MapOptions) (*Map, error) {
	tb.Helper()

	spec = fixupMapSpec(spec)

	if opts == nil {
		opts = new(MapOptions)
	}

	m, err := NewMapWithOptions(spec, *opts)
	testutils.SkipIfNotSupportedOnOS(tb, err)
	if err != nil {
		return nil, err
	}

	tb.Cleanup(func() { m.Close() })
	return m, nil
}

func mustNewMap(tb testing.TB, spec *MapSpec, opts *MapOptions) *Map {
	tb.Helper()

	m, err := newMap(tb, spec, opts)
	qt.Assert(tb, qt.IsNil(err))

	return m
}

func createMap(tb testing.TB, typ MapType, maxEntries uint32) *Map {
	tb.Helper()

	return mustNewMap(tb, &MapSpec{
		Name:       "test",
		Type:       typ,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: maxEntries,
	}, nil)
}

func createMapInMap(tb testing.TB, outer, inner MapType) *Map {
	tb.Helper()

	return mustNewMap(tb, &MapSpec{
		Type:       outer,
		KeySize:    4,
		MaxEntries: 2,
		InnerMap: &MapSpec{
			Type:       inner,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 2,
		},
	}, nil)
}

func newProgram(tb testing.TB, spec *ProgramSpec, opts *ProgramOptions) (*Program, error) {
	tb.Helper()

	if opts == nil {
		opts = new(ProgramOptions)
	}

	spec = fixupProgramSpec(spec)

	prog, err := NewProgramWithOptions(spec, *opts)
	testutils.SkipIfNotSupportedOnOS(tb, err)
	if err != nil {
		return nil, err
	}

	tb.Cleanup(func() { prog.Close() })
	return prog, nil
}

func mustNewProgram(tb testing.TB, spec *ProgramSpec, opts *ProgramOptions) *Program {
	tb.Helper()

	prog, err := newProgram(tb, spec, opts)
	qt.Assert(tb, qt.IsNil(err))
	return prog
}

func createProgram(tb testing.TB, typ ProgramType, retval int64) *Program {
	tb.Helper()

	return mustNewProgram(tb, &ProgramSpec{
		Name: "test",
		Type: typ,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, retval, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	}, nil)
}

var basicProgramSpec = &ProgramSpec{
	Name: "test",
	Type: SocketFilter,
	Instructions: asm.Instructions{
		asm.LoadImm(asm.R0, 2, asm.DWord),
		asm.Return(),
	},
	License: "MIT",
}

// createBasicProgram returns a program of an unspecified type which returns
// a non-zero value when executed.
func createBasicProgram(tb testing.TB) *Program {
	return mustNewProgram(tb, basicProgramSpec, nil)
}

func newCollection(tb testing.TB, spec *CollectionSpec, opts *CollectionOptions) (*Collection, error) {
	tb.Helper()

	spec = fixupCollectionSpec(spec)

	if opts == nil {
		opts = new(CollectionOptions)
	}

	c, err := NewCollectionWithOptions(spec, *opts)
	testutils.SkipIfNotSupportedOnOS(tb, err)
	if err != nil {
		return nil, err
	}

	tb.Cleanup(func() { c.Close() })
	return c, nil
}

func mustNewCollection(tb testing.TB, spec *CollectionSpec, opts *CollectionOptions) *Collection {
	tb.Helper()
	c, err := newCollection(tb, spec, opts)
	qt.Assert(tb, qt.IsNil(err))
	return c
}

func loadAndAssign(tb testing.TB, spec *CollectionSpec, to any, opts *CollectionOptions) error {
	tb.Helper()
	spec = fixupCollectionSpec(spec)
	err := spec.LoadAndAssign(to, opts)
	testutils.SkipIfNotSupported(tb, err)
	return err
}

func mustLoadAndAssign(tb testing.TB, spec *CollectionSpec, to any, opts *CollectionOptions) {
	qt.Assert(tb, qt.IsNil(loadAndAssign(tb, spec, to, opts)))
}

func mustRun(tb testing.TB, prog *Program, opts *RunOptions) (retval uint32) {
	tb.Helper()

	if opts == nil {
		opts = &RunOptions{}
	}
	if platform.IsLinux && opts.Data == nil {
		opts.Data = internal.EmptyBPFContext
	}
	if platform.IsWindows {
		switch prog.Type() {
		case WindowsSample:
			const minSampleContextLen = 32

			if opts.Context == nil {
				opts.Context = make([]byte, minSampleContextLen)
			}
		}
	}

	ret, err := prog.Run(opts)
	testutils.SkipIfNotSupported(tb, err)
	qt.Assert(tb, qt.IsNil(err))

	return ret
}

// The functions below translate Linux types to their Windows equivalents, if
// possible. This allows running most tests on Windows without modification.

func fixupMapType(typ MapType) MapType {
	if !platform.IsWindows {
		return typ
	}

	switch typ {
	case Array:
		return WindowsArray
	case Hash:
		return WindowsHash
	case ProgramArray:
		return WindowsProgramArray
	case PerCPUHash:
		return WindowsPerCPUHash
	case PerCPUArray:
		return WindowsPerCPUArray
	case LRUHash:
		return WindowsLRUHash
	case LRUCPUHash:
		return WindowsLRUCPUHash
	case ArrayOfMaps:
		return WindowsArrayOfMaps
	case HashOfMaps:
		return WindowsHashOfMaps
	case LPMTrie:
		return WindowsLPMTrie
	case Queue:
		return WindowsQueue
	case Stack:
		return WindowsStack
	case RingBuf:
		return WindowsRingBuf
	default:
		return typ
	}
}

func fixupMapSpec(spec *MapSpec) *MapSpec {
	if !platform.IsWindows {
		return spec
	}

	spec = spec.Copy()
	spec.Type = fixupMapType(spec.Type)
	if spec.InnerMap != nil {
		spec.InnerMap.Type = fixupMapType(spec.InnerMap.Type)
	}

	return spec
}

func fixupProgramType(typ ProgramType) ProgramType {
	if !platform.IsWindows {
		return typ
	}

	switch typ {
	case SocketFilter:
		return WindowsSample
	case XDP:
		return WindowsSample
	default:
		return typ
	}
}

func fixupProgramSpec(spec *ProgramSpec) *ProgramSpec {
	if !platform.IsWindows {
		return spec
	}

	spec = spec.Copy()
	spec.Type = fixupProgramType(spec.Type)

	for i, ins := range spec.Instructions {
		if ins.IsBuiltinCall() {
			switch asm.BuiltinFunc(ins.Constant) {
			case asm.FnMapUpdateElem:
				spec.Instructions[i].Constant = int64(asm.WindowsFnMapUpdateElem)
			case asm.FnMapLookupElem:
				spec.Instructions[i].Constant = int64(asm.WindowsFnMapLookupElem)
			case asm.FnTailCall:
				spec.Instructions[i].Constant = int64(asm.WindowsFnTailCall)
			}
		}
	}

	return spec
}

func fixupCollectionSpec(spec *CollectionSpec) *CollectionSpec {
	if !platform.IsWindows {
		return spec
	}

	spec = spec.Copy()
	for name := range spec.Maps {
		spec.Maps[name] = fixupMapSpec(spec.Maps[name])
	}

	for name := range spec.Programs {
		spec.Programs[name] = fixupProgramSpec(spec.Programs[name])
	}

	return spec
}
