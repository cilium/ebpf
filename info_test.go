package ebpf

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"
	qt "github.com/frankban/quicktest"
)

func TestMapInfoFromProc(t *testing.T) {
	hash, err := NewMap(&MapSpec{
		Name:       "testing",
		Type:       Hash,
		KeySize:    4,
		ValueSize:  5,
		MaxEntries: 2,
		Flags:      unix.BPF_F_NO_PREALLOC,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hash.Close()

	info, err := newMapInfoFromProc(hash.fd)
	if err != nil {
		t.Fatal("Can't get map info:", err)
	}

	if info.Type != Hash {
		t.Error("Expected Hash, got", info.Type)
	}

	if info.KeySize != 4 {
		t.Error("Expected KeySize of 4, got", info.KeySize)
	}

	if info.ValueSize != 5 {
		t.Error("Expected ValueSize of 5, got", info.ValueSize)
	}

	if info.MaxEntries != 2 {
		t.Error("Expected MaxEntries of 2, got", info.MaxEntries)
	}

	if info.Flags != unix.BPF_F_NO_PREALLOC {
		t.Errorf("Expected Flags to be %d, got %d", unix.BPF_F_NO_PREALLOC, info.Flags)
	}

	if info.Name != "" && info.Name != "testing" {
		t.Error("Expected name to be testing, got", info.Name)
	}

	if _, ok := info.ID(); ok {
		t.Error("Expected ID to not be available")
	}

	nested, err := NewMap(&MapSpec{
		Type:       ArrayOfMaps,
		KeySize:    4,
		MaxEntries: 2,
		InnerMap: &MapSpec{
			Type:       Array,
			KeySize:    4,
			ValueSize:  4,
			MaxEntries: 2,
		},
	})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer nested.Close()

	_, err = newMapInfoFromProc(nested.fd)
	if err != nil {
		t.Fatal("Can't get nested map info from /proc:", err)
	}
}

func TestProgramInfo(t *testing.T) {
	prog := createSocketFilter(t)
	defer prog.Close()

	for name, fn := range map[string]func(*internal.FD) (*ProgramInfo, error){
		"generic": newProgramInfoFromFd,
		"proc":    newProgramInfoFromProc,
	} {
		t.Run(name, func(t *testing.T) {
			info, err := fn(prog.fd)
			testutils.SkipIfNotSupported(t, err)
			if err != nil {
				t.Fatal("Can't get program info:", err)
			}

			if info.Type != SocketFilter {
				t.Error("Expected Type to be SocketFilter, got", info.Type)
			}

			if info.Name != "" && info.Name != "test" {
				t.Error("Expected Name to be test, got", info.Name)
			}

			if want := "d7edec644f05498d"; info.Tag != want {
				t.Errorf("Expected Tag to be %s, got %s", want, info.Tag)
			}

			if id, ok := info.ID(); ok && id == 0 {
				t.Error("Expected a valid ID:", id)
			} else if name == "proc" && ok {
				t.Error("Expected ID to not be available")
			}
		})
	}
}

func TestProgramInfoMapIDs(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.10", "reading program info")

	arr, err := NewMap(&MapSpec{
		Type:       Array,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	qt.Assert(t, err, qt.IsNil)
	defer arr.Close()

	prog, err := NewProgram(&ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadMapPtr(asm.R0, arr.FD()),
			asm.LoadImm(asm.R0, 2, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	})
	qt.Assert(t, err, qt.IsNil)
	defer prog.Close()

	info, err := prog.Info()
	qt.Assert(t, err, qt.IsNil)

	ids, ok := info.MapIDs()
	if testutils.MustKernelVersion().Less(internal.Version{4, 15, 0}) {
		qt.Assert(t, ok, qt.IsFalse)
		qt.Assert(t, ids, qt.HasLen, 0)
	} else {
		qt.Assert(t, ok, qt.IsTrue)
		qt.Assert(t, ids, qt.HasLen, 1)

		mapInfo, err := arr.Info()
		qt.Assert(t, err, qt.IsNil)
		mapID, ok := mapInfo.ID()
		qt.Assert(t, ok, qt.IsTrue)
		qt.Assert(t, ids[0], qt.Equals, mapID)
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

	spec := &ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 42, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	}

	prog, err := NewProgram(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

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
	if rt != 0 {
		t.Errorf("expected a runtime of 0ns but got %v", rt)
	}

	if err := testStats(prog); err != nil {
		t.Error(err)
	}
}

// BenchmarkStats is a benchmark of TestStats. See testStats for details.
func BenchmarkStats(b *testing.B) {
	testutils.SkipOnOldKernel(b, "5.8", "BPF_ENABLE_STATS")

	spec := &ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 42, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	}

	// Don't insert the program in a loop as it causes a flood of kaudit messages.
	prog, err := NewProgram(spec)
	if err != nil {
		b.Fatal(err)
	}
	defer prog.Close()

	for n := 0; n < b.N; n++ {
		if err := testStats(prog); err != nil {
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
	in := make([]byte, 14)

	stats, err := EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		return fmt.Errorf("failed to enable stats: %v", err)
	}
	defer stats.Close()

	// Program execution with runtime statistics enabled.
	// Should increase both runtime and run counter.
	if _, _, err := prog.Test(in); err != nil {
		return fmt.Errorf("failed to trigger program: %v", err)
	}

	pi, err := prog.Info()
	if err != nil {
		return fmt.Errorf("failed to get ProgramInfo: %v", err)
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
		return fmt.Errorf("failed to disable statistics: %v", err)
	}

	// Second program execution, with runtime statistics gathering disabled.
	// Total runtime and run counters are not expected to increase.
	if _, _, err := prog.Test(in); err != nil {
		return fmt.Errorf("failed to trigger program: %v", err)
	}

	pi, err = prog.Info()
	if err != nil {
		return fmt.Errorf("failed to get ProgramInfo: %v", err)
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
