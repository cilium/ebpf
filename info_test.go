package ebpf

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
)

var btfFn = &btf.Func{
	Name: "_",
	Type: &btf.FuncProto{
		Return: &btf.Int{Size: 16},
		Params: []btf.FuncParam{},
	},
	Linkage: btf.StaticFunc,
}

var multiprogSpec = &ProgramSpec{
	Name: "test",
	Type: SocketFilter,
	Instructions: asm.Instructions{
		btf.WithFuncMetadata(asm.LoadImm(asm.R0, 0, asm.DWord), btfFn).
			WithSource(asm.Comment("line info")),
		asm.Call.Label("fn"),
		asm.Return(),
		btf.WithFuncMetadata(asm.LoadImm(asm.R0, 0, asm.DWord), btfFn).
			WithSource(asm.Comment("line info")).WithSymbol("fn"),
		asm.Return(),
	},
	License: "MIT",
}

func TestMapInfoFromProc(t *testing.T) {
	hash := mustNewMap(t, &MapSpec{
		Type:       Hash,
		KeySize:    4,
		ValueSize:  5,
		MaxEntries: 2,
		Flags:      sys.BPF_F_NO_PREALLOC,
	}, nil)

	var info MapInfo
	err := readMapInfoFromProc(hash.fd, &info)
	testutils.SkipIfNotSupported(t, err)

	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(info.Type, Hash))
	qt.Assert(t, qt.Equals(info.KeySize, 4))
	qt.Assert(t, qt.Equals(info.ValueSize, 5))
	qt.Assert(t, qt.Equals(info.MaxEntries, 2))
	qt.Assert(t, qt.Equals(info.Flags, sys.BPF_F_NO_PREALLOC))
}

func TestMapInfoFromProcOuterMap(t *testing.T) {
	outer := mustNewMap(t, &MapSpec{
		Type:       ArrayOfMaps,
		KeySize:    4,
		MaxEntries: 2,
		InnerMap: &MapSpec{
			Type:       Array,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 2,
		},
	}, nil)

	var info MapInfo
	err := readMapInfoFromProc(outer.fd, &info)
	testutils.SkipIfNotSupported(t, err)

	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(info.KeySize, 4))
	qt.Assert(t, qt.Equals(info.MaxEntries, 2))
}

func validateProgInfo(t *testing.T, spec *ProgramSpec, info *ProgramInfo) {
	t.Helper()

	qt.Assert(t, qt.Equals(info.Type, spec.Type))
	if info.Tag != "" {
		qt.Assert(t, qt.Equals(info.Tag, "d7edec644f05498d"))
	}
}

func TestProgramInfo(t *testing.T) {
	spec := fixupProgramSpec(basicProgramSpec)
	prog := mustNewProgram(t, spec, nil)

	info, err := newProgramInfoFromFd(prog.fd)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	validateProgInfo(t, spec, info)

	id, ok := info.ID()
	qt.Assert(t, qt.IsTrue(ok))
	qt.Assert(t, qt.Not(qt.Equals(id, 0)))

	if testutils.IsVersionLessThan(t, "4.15", "windows:0.20") {
		qt.Assert(t, qt.Equals(info.Name, ""))
	} else {
		qt.Assert(t, qt.Equals(info.Name, "test"))
	}

	if jitedSize, err := info.JitedSize(); testutils.IsVersionLessThan(t, "4.13") {
		qt.Assert(t, qt.IsNotNil(err))
	} else {
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsTrue(jitedSize > 0))
	}

	if xlatedSize, err := info.TranslatedSize(); testutils.IsVersionLessThan(t, "4.13") {
		qt.Assert(t, qt.IsNotNil(err))
	} else {
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsTrue(xlatedSize > 0))
	}

	if uid, ok := info.CreatedByUID(); testutils.IsVersionLessThan(t, "4.15") {
		qt.Assert(t, qt.IsFalse(ok))
	} else {
		qt.Assert(t, qt.IsTrue(ok))
		qt.Assert(t, qt.Equals(uid, uint32(os.Getuid())))
	}

	if loadTime, ok := info.LoadTime(); testutils.IsVersionLessThan(t, "4.15") {
		qt.Assert(t, qt.IsFalse(ok))
	} else {
		qt.Assert(t, qt.IsTrue(ok))
		qt.Assert(t, qt.IsTrue(loadTime > 0))
	}

	if verifiedInsns, ok := info.VerifiedInstructions(); testutils.IsVersionLessThan(t, "5.16") {
		qt.Assert(t, qt.IsFalse(ok))
	} else {
		qt.Assert(t, qt.IsTrue(ok))
		qt.Assert(t, qt.IsTrue(verifiedInsns > 0))
	}

	if insns, ok := info.JitedInsns(); testutils.IsVersionLessThan(t, "4.13") {
		qt.Assert(t, qt.IsFalse(ok))
	} else {
		qt.Assert(t, qt.IsTrue(ok))
		qt.Assert(t, qt.IsTrue(len(insns) > 0))
	}
}

func TestProgramInfoProc(t *testing.T) {
	spec := fixupProgramSpec(basicProgramSpec)
	prog := mustNewProgram(t, spec, nil)

	info, err := newProgramInfoFromProc(prog.fd)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	validateProgInfo(t, spec, info)
}

func TestProgramInfoBTF(t *testing.T) {
	prog, err := newProgram(t, multiprogSpec, nil)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	info, err := prog.Info()
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	// On kernels before 5.x, nr_jited_ksyms is not set for programs without subprogs.
	// It's included here since this test uses a bpf program with subprogs.
	if addrs, ok := info.JitedKsymAddrs(); testutils.IsVersionLessThan(t, "4.18") {
		qt.Assert(t, qt.IsFalse(ok))
	} else {
		qt.Assert(t, qt.IsTrue(ok))
		qt.Assert(t, qt.IsTrue(len(addrs) > 0))
	}

	if lens, ok := info.JitedFuncLens(); testutils.IsVersionLessThan(t, "4.18") {
		qt.Assert(t, qt.IsFalse(ok))
	} else {
		qt.Assert(t, qt.IsTrue(ok))
		qt.Assert(t, qt.IsTrue(len(lens) > 0))
	}

	if infos, ok := info.JitedLineInfos(); testutils.IsVersionLessThan(t, "5.0") {
		qt.Assert(t, qt.IsFalse(ok))
	} else {
		qt.Assert(t, qt.IsTrue(ok))
		qt.Assert(t, qt.IsTrue(len(infos) > 0))
	}

	if funcs, err := info.FuncInfos(); testutils.IsVersionLessThan(t, "5.0") {
		qt.Assert(t, qt.IsNotNil(err))
	} else {
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.HasLen(funcs, 2))
		qt.Assert(t, qt.ContentEquals(funcs[0].Func, btfFn))
		qt.Assert(t, qt.ContentEquals(funcs[1].Func, btfFn))
	}

	if lines, err := info.LineInfos(); testutils.IsVersionLessThan(t, "5.0") {
		qt.Assert(t, qt.IsNotNil(err))
	} else {
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.HasLen(lines, 2))
		qt.Assert(t, qt.Equals(lines[0].Line.Line(), "line info"))
		qt.Assert(t, qt.Equals(lines[1].Line.Line(), "line info"))
	}
}

func TestProgramInfoMapIDs(t *testing.T) {
	arr := createMap(t, Array, 1)

	prog := mustNewProgram(t, &ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R0, arr.FD()),
			asm.LoadImm(asm.R0, 2, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	}, nil)

	info, err := prog.Info()
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	ids, ok := info.MapIDs()
	switch {
	case testutils.IsVersionLessThan(t, "4.15", "windows:0.20"):
		qt.Assert(t, qt.IsFalse(ok))
		qt.Assert(t, qt.HasLen(ids, 0))

	default:
		qt.Assert(t, qt.IsTrue(ok))

		mapInfo, err := arr.Info()
		qt.Assert(t, qt.IsNil(err))

		mapID, ok := mapInfo.ID()
		qt.Assert(t, qt.IsTrue(ok))
		qt.Assert(t, qt.ContentEquals(ids, []MapID{mapID}))
	}
}

func TestProgramInfoMapIDsNoMaps(t *testing.T) {
	prog := createBasicProgram(t)

	info, err := prog.Info()
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	ids, ok := info.MapIDs()
	switch {
	case testutils.IsVersionLessThan(t, "4.15", "windows:0.20"):
		qt.Assert(t, qt.IsFalse(ok))
		qt.Assert(t, qt.HasLen(ids, 0))

	default:
		qt.Assert(t, qt.IsTrue(ok))
		qt.Assert(t, qt.HasLen(ids, 0))
	}
}

func TestScanFdInfoReader(t *testing.T) {
	tests := []struct {
		fields map[string]interface{}
		valid  bool
	}{
		{nil, true},
		{map[string]interface{}{"foo": new(string)}, true},
		{map[string]interface{}{"zap": new(string)}, false},
		{map[string]interface{}{"foo": new(int)}, false},
	}

	for _, test := range tests {
		err := scanFdInfoReader(strings.NewReader("foo:\tbar\n"), test.fields)
		if test.valid {
			if err != nil {
				t.Errorf("fields %v returns an error: %s", test.fields, err)
			}
		} else {
			if err == nil {
				t.Errorf("fields %v doesn't return an error", test.fields)
			}
		}
	}
}

// TestStats loads a BPF program once and executes back-to-back test runs
// of the program. See testStats for details.
func TestStats(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF_ENABLE_STATS")

	prog := createBasicProgram(t)

	pi, err := prog.Info()
	if err != nil {
		t.Errorf("failed to get ProgramInfo: %v", err)
	}

	rc, ok := pi.RunCount()
	if !ok {
		t.Errorf("expected run count info to be available")
	}
	if rc != 0 {
		t.Errorf("expected a run count of 0 but got %d", rc)
	}

	rt, ok := pi.Runtime()
	if !ok {
		t.Errorf("expected runtime info to be available")
	}
	if runtime.GOARCH != "arm64" && rt != 0 {
		t.Errorf("expected a runtime of 0ns but got %v", rt)
	}

	rm, ok := pi.RecursionMisses()
	if !ok {
		t.Errorf("expected recursion misses info to be available")
	}
	if rm != 0 {
		t.Errorf("expected a recursion misses of 0 but got %v", rm)
	}

	if err := testStats(prog); err != nil {
		testutils.SkipIfNotSupportedOnOS(t, err)
		t.Error(err)
	}
}

// BenchmarkStats is a benchmark of TestStats. See testStats for details.
func BenchmarkStats(b *testing.B) {
	testutils.SkipOnOldKernel(b, "5.8", "BPF_ENABLE_STATS")

	prog := createBasicProgram(b)

	for n := 0; n < b.N; n++ {
		if err := testStats(prog); err != nil {
			testutils.SkipIfNotSupportedOnOS(b, err)
			b.Fatal(fmt.Errorf("iter %d: %w", n, err))
		}
	}
}

// testStats implements the behaviour under test for TestStats
// and BenchmarkStats. First, a test run is executed with runtime statistics
// enabled, followed by another with runtime stats disabled. Counters are only
// expected to increase on the runs where runtime stats are enabled.
//
// Due to runtime behaviour on Go 1.14 and higher, the syscall backing
// (*Program).Test() could be invoked multiple times for each call to Test(),
// resulting in RunCount incrementing by more than one. Expecting RunCount to
// be of a specific value after a call to Test() is therefore not possible.
// See https://golang.org/doc/go1.14#runtime for more details.
func testStats(prog *Program) error {
	in := internal.EmptyBPFContext

	stats, err := EnableStats(uint32(sys.BPF_STATS_RUN_TIME))
	if err != nil {
		return fmt.Errorf("failed to enable stats: %w", err)
	}
	defer stats.Close()

	// Program execution with runtime statistics enabled.
	// Should increase both runtime and run counter.
	if _, _, err := prog.Test(in); err != nil {
		return fmt.Errorf("failed to trigger program: %w", err)
	}

	pi, err := prog.Info()
	if err != nil {
		return fmt.Errorf("failed to get ProgramInfo: %w", err)
	}

	rc, ok := pi.RunCount()
	if !ok {
		return errors.New("expected run count info to be available")
	}
	if rc < 1 {
		return fmt.Errorf("expected a run count of at least 1 but got %d", rc)
	}
	// Store the run count for the next invocation.
	lc := rc

	rt, ok := pi.Runtime()
	if !ok {
		return errors.New("expected runtime info to be available")
	}
	if rt == 0 {
		return errors.New("expected a runtime other than 0ns")
	}
	// Store the runtime value for the next invocation.
	lt := rt

	if err := stats.Close(); err != nil {
		return fmt.Errorf("failed to disable statistics: %w", err)
	}

	// Second program execution, with runtime statistics gathering disabled.
	// Total runtime and run counters are not expected to increase.
	if _, _, err := prog.Test(in); err != nil {
		return fmt.Errorf("failed to trigger program: %w", err)
	}

	pi, err = prog.Info()
	if err != nil {
		return fmt.Errorf("failed to get ProgramInfo: %w", err)
	}

	rc, ok = pi.RunCount()
	if !ok {
		return errors.New("expected run count info to be available")
	}
	if rc != lc {
		return fmt.Errorf("run count unexpectedly increased over previous value (current: %v, prev: %v)", rc, lc)
	}

	rt, ok = pi.Runtime()
	if !ok {
		return errors.New("expected runtime info to be available")
	}
	if rt != lt {
		return fmt.Errorf("runtime unexpectedly increased over the previous value (current: %v, prev: %v)", rt, lt)
	}

	return nil
}

func TestHaveProgramInfoMapIDs(t *testing.T) {
	testutils.CheckFeatureTest(t, haveProgramInfoMapIDs)
}

func TestProgInfoExtBTF(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.0", "Program BTF (func/line_info)")

	spec, err := LoadCollectionSpec(testutils.NativeFile(t, "testdata/loader-%s.elf"))
	if err != nil {
		t.Fatal(err)
	}

	var obj struct {
		Main *Program `ebpf:"xdp_prog"`
	}

	err = loadAndAssign(t, spec, &obj, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Main.Close()

	info, err := obj.Main.Info()
	if err != nil {
		t.Fatal(err)
	}

	inst, err := info.Instructions()
	if err != nil {
		t.Fatal(err)
	}

	expectedLineInfoCount := 28
	expectedFuncInfo := map[string]bool{
		"xdp_prog":   false,
		"static_fn":  false,
		"global_fn2": false,
		"global_fn3": false,
	}

	lineInfoCount := 0

	for _, ins := range inst {
		if ins.Source() != nil {
			lineInfoCount++
		}

		fn := btf.FuncMetadata(&ins)
		if fn != nil {
			expectedFuncInfo[fn.Name] = true
		}
	}

	if lineInfoCount != expectedLineInfoCount {
		t.Errorf("expected %d line info entries, got %d", expectedLineInfoCount, lineInfoCount)
	}

	for fn, found := range expectedFuncInfo {
		if !found {
			t.Errorf("func %q not found", fn)
		}
	}
}

func TestInfoExportedFields(t *testing.T) {
	// It is highly unlikely that you should be adjusting the asserts below.
	// See the comment at the top of info.go for more information.

	var names []string
	for _, field := range reflect.VisibleFields(reflect.TypeOf(MapInfo{})) {
		if field.IsExported() {
			names = append(names, field.Name)
		}
	}
	qt.Assert(t, qt.ContentEquals(names, []string{
		"Type",
		"KeySize",
		"ValueSize",
		"MaxEntries",
		"Flags",
		"Name",
	}))

	names = nil
	for _, field := range reflect.VisibleFields(reflect.TypeOf(ProgramInfo{})) {
		if field.IsExported() {
			names = append(names, field.Name)
		}
	}
	qt.Assert(t, qt.ContentEquals(names, []string{
		"Type",
		"Tag",
		"Name",
	}))
}

func TestZero(t *testing.T) {
	var (
		nul uint32 = 0
		one uint32 = 1

		inul any = uint32(0)
		ione any = uint32(1)
	)

	qt.Assert(t, qt.IsTrue(zero(nul)))
	qt.Assert(t, qt.IsFalse(zero(one)))

	qt.Assert(t, qt.IsTrue(zero(&nul)))
	qt.Assert(t, qt.IsFalse(zero(&one)))

	qt.Assert(t, qt.IsTrue(zero(inul)))
	qt.Assert(t, qt.IsFalse(zero(ione)))

	qt.Assert(t, qt.IsTrue(zero(&inul)))
	qt.Assert(t, qt.IsFalse(zero(&ione)))
}
