package ebpf

import (
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

var hashMapSpec = &MapSpec{
	Type:       Hash,
	KeySize:    4,
	ValueSize:  5,
	MaxEntries: 2,
	Flags:      sys.BPF_F_NO_PREALLOC,
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

func validateMapInfo(t *testing.T, info *MapInfo, spec *MapSpec) {
	t.Helper()

	qt.Assert(t, qt.Equals(info.Type, spec.Type))
	qt.Assert(t, qt.Equals(info.KeySize, spec.KeySize))
	qt.Assert(t, qt.Equals(info.ValueSize, spec.ValueSize))
	qt.Assert(t, qt.Equals(info.MaxEntries, spec.MaxEntries))
	qt.Assert(t, qt.Equals(info.Flags, spec.Flags))

	memlock, _ := info.Memlock()
	qt.Assert(t, qt.Not(qt.Equals(memlock, 0)))
}

func TestMapInfo(t *testing.T) {
	m := mustNewMap(t, hashMapSpec, nil)

	info, err := m.Info()
	qt.Assert(t, qt.IsNil(err))

	validateMapInfo(t, info, hashMapSpec)
}

func TestMapInfoFromProc(t *testing.T) {
	hash := mustNewMap(t, hashMapSpec, nil)

	var info MapInfo
	err := readMapInfoFromProc(hash.fd, &info)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	validateMapInfo(t, &info, hashMapSpec)
}

func TestMapInfoFromProcOuterMap(t *testing.T) {
	outer := &MapSpec{
		Type:       ArrayOfMaps,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 2,
		InnerMap: &MapSpec{
			Type:       Array,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 2,
		},
	}
	m := mustNewMap(t, outer, nil)

	var info MapInfo
	err := readMapInfoFromProc(m.fd, &info)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	validateMapInfo(t, &info, outer)
}

func BenchmarkNewMapFromFD(b *testing.B) {
	b.ReportAllocs()

	m := mustNewMap(b, hashMapSpec, nil)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, err := newMapFromFD(m.fd); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMapInfo(b *testing.B) {
	b.ReportAllocs()

	m := mustNewMap(b, hashMapSpec, nil)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, err := newMapInfoFromFd(m.fd); err != nil {
			b.Fatal(err)
		}
	}
}

func validateProgInfo(t *testing.T, spec *ProgramSpec, info *ProgramInfo) {
	t.Helper()

	qt.Assert(t, qt.Equals(info.Type, spec.Type))
	if info.Tag != "" {
		qt.Assert(t, qt.Equals(info.Tag, "d7edec644f05498d"))
	}
	memlock, ok := info.Memlock()
	if ok {
		qt.Assert(t, qt.Equals(memlock, 4096))
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

func BenchmarkNewProgramFromFD(b *testing.B) {
	b.ReportAllocs()

	spec := fixupProgramSpec(basicProgramSpec)
	prog := mustNewProgram(b, spec, nil)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, err := newProgramFromFD(prog.fd); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProgramInfo(b *testing.B) {
	b.ReportAllocs()

	spec := fixupProgramSpec(basicProgramSpec)
	prog := mustNewProgram(b, spec, nil)

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		if _, err := newProgramInfoFromFd(prog.fd); err != nil {
			b.Fatal(err)
		}
	}
}

func TestProgramInfoProc(t *testing.T) {
	spec := fixupProgramSpec(basicProgramSpec)
	prog := mustNewProgram(t, spec, nil)

	var info ProgramInfo
	err := readProgramInfoFromProc(prog.fd, &info)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	validateProgInfo(t, spec, &info)
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

func BenchmarkScanFdInfoReader(b *testing.B) {
	b.ReportAllocs()

	// Pathological case with 9 fields we're not interested in, and one
	// field we are, all the way at the very end.
	input := strings.Repeat("ignore:\tthis\n", 9)
	input += "foo:\tbar\n"
	r := strings.NewReader(input)

	var val string
	fields := map[string]any{"foo": &val}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		val = ""
		r.Reset(input)

		if err := scanFdInfoReader(r, fields); err != nil {
			b.Fatal(err)
		}
		if val != "bar" {
			b.Fatal("unexpected value:", val)
		}
	}
}

// TestProgramStats loads a BPF program once and executes back-to-back test runs
// of the program. See testStats for details.
func TestProgramStats(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.8", "BPF_ENABLE_STATS")

	prog := createBasicProgram(t)

	s, err := prog.Stats()
	qt.Assert(t, qt.IsNil(err))

	qt.Assert(t, qt.Equals(s.RunCount, 0))
	qt.Assert(t, qt.Equals(s.RecursionMisses, 0))

	if runtime.GOARCH != "arm64" {
		// Runtime is flaky on arm64.
		qt.Assert(t, qt.Equals(s.Runtime, 0))
	}

	if err := testStats(t, prog); err != nil {
		testutils.SkipIfNotSupportedOnOS(t, err)
		t.Error(err)
	}
}

// BenchmarkStats is a benchmark of TestStats. See testStats for details.
func BenchmarkStats(b *testing.B) {
	b.ReportAllocs()

	testutils.SkipOnOldKernel(b, "5.8", "BPF_ENABLE_STATS")

	prog := createBasicProgram(b)

	for n := 0; n < b.N; n++ {
		if err := testStats(b, prog); err != nil {
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
func testStats(tb testing.TB, prog *Program) error {
	tb.Helper()

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

	s1, err := prog.Stats()
	qt.Assert(tb, qt.IsNil(err))

	qt.Assert(tb, qt.Not(qt.Equals(s1.RunCount, 0)), qt.Commentf("expected run count to be at least 1 after first invocation"))
	qt.Assert(tb, qt.Not(qt.Equals(s1.Runtime, 0)), qt.Commentf("expected runtime to be at least 1ns after first invocation"))

	qt.Assert(tb, qt.IsNil(stats.Close()))

	// Second program execution, with runtime statistics gathering disabled.
	// Total runtime and run counters are not expected to increase.
	if _, _, err := prog.Test(in); err != nil {
		return fmt.Errorf("failed to trigger program: %w", err)
	}

	s2, err := prog.Stats()
	qt.Assert(tb, qt.IsNil(err))

	qt.Assert(tb, qt.Equals(s2.RunCount, s1.RunCount), qt.Commentf("run count (%d) increased after first invocation (%d)", s2.RunCount, s1.RunCount))
	qt.Assert(tb, qt.Equals(s2.Runtime, s1.Runtime), qt.Commentf("runtime (%d) increased after first invocation (%d)", s2.Runtime, s1.Runtime))

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
		empty        = ""
		nul   uint32 = 0
		one   uint32 = 1

		iempty any = ""
		inul   any = uint32(0)
		ione   any = uint32(1)
	)

	qt.Assert(t, qt.IsTrue(zero(empty)))
	qt.Assert(t, qt.IsTrue(zero(nul)))
	qt.Assert(t, qt.IsFalse(zero(one)))

	qt.Assert(t, qt.IsTrue(zero(&empty)))
	qt.Assert(t, qt.IsTrue(zero(&nul)))
	qt.Assert(t, qt.IsFalse(zero(&one)))

	qt.Assert(t, qt.IsTrue(zero(iempty)))
	qt.Assert(t, qt.IsTrue(zero(inul)))
	qt.Assert(t, qt.IsFalse(zero(ione)))

	qt.Assert(t, qt.IsTrue(zero(&iempty)))
	qt.Assert(t, qt.IsTrue(zero(&inul)))
	qt.Assert(t, qt.IsFalse(zero(&ione)))
}
