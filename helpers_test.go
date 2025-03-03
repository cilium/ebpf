package ebpf

import (
	"errors"
	"sync"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal/testutils"
)

var haveTestmod = sync.OnceValues(func() (bool, error) {
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

func newMap(tb testing.TB, spec *MapSpec, opts *MapOptions) (*Map, error) {
	tb.Helper()

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

	prog, err := NewProgramWithOptions(spec, *opts)
	testutils.SkipIfNotSupportedOnOS(tb, err)
	if err != nil {
		return nil, err
	}

	tb.Cleanup(func() { prog.Close() })
	return prog, nil
}

func mustNewProgram(tb testing.TB, spec *ProgramSpec, opts *ProgramOptions) *Program {
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

	if opts == nil {
		opts = new(CollectionOptions)
	}

	c, err := NewCollectionWithOptions(spec, *opts)
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
	err := spec.LoadAndAssign(to, opts)
	testutils.SkipIfNotSupported(tb, err)
	return err
}

func mustLoadAndAssign(tb testing.TB, spec *CollectionSpec, to any, opts *CollectionOptions) {
	qt.Assert(tb, qt.IsNil(loadAndAssign(tb, spec, to, opts)))
}
