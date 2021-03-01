package ebpf

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"
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

	progInfo, err := prog.Info()
	if err != nil {
		t.Errorf("failed to get ProgramInfo: %v", err)
	}

	if cnt, available := progInfo.RunCount(); cnt != 0 || !available {
		t.Errorf("expected a run count of 0 but got %d", cnt)
	}

	if runtime, available := progInfo.Runtime(); runtime != 0 || !available {
		t.Errorf("expected a runtime of 0ns but got %v", runtime)
	}

	disableStats, err := EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
	if err != nil {
		t.Fatalf("failed to enable stats: %v", err)
	}
	defer disableStats.Close()

	if _, _, err := prog.Test(make([]byte, 14)); err != nil {
		t.Errorf("failed to trigger program: %v", err)
	}

	progInfo2, err := prog.Info()
	if err != nil {
		t.Errorf("failed to get ProgramInfo: %v", err)
	}

	if cnt, available := progInfo2.RunCount(); cnt != 1 || !available {
		t.Errorf("expected a run count of 1 but got %d", cnt)
	}

	if runtime, available := progInfo2.Runtime(); runtime == 0 || !available {
		t.Errorf("expected a runtime other than 0ns")
	}

	if err := disableStats.Close(); err != nil {
		t.Errorf("failed to disable statistics: %v", err)
	}

	if _, _, err := prog.Test(make([]byte, 14)); err != nil {
		t.Errorf("failed to trigger program: %v", err)
	}

	progInfo3, err := prog.Info()
	if err != nil {
		t.Errorf("failed to get ProgramInfo: %v", err)
	}

	if cnt, available := progInfo3.RunCount(); cnt != 1 || !available {
		t.Errorf("expected a run count of 1 but got %d", cnt)
	}

	if runtime, available := progInfo3.Runtime(); runtime == 0 || !available {
		t.Errorf("expected a runtime other than 0ns")
	}
}
