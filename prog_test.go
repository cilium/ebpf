package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"
)

func TestProgramRun(t *testing.T) {
	pat := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	buf := internal.EmptyBPFContext

	// r1  : ctx_start
	// r1+4: ctx_end
	ins := asm.Instructions{
		// r2 = *(r1+4)
		asm.LoadMem(asm.R2, asm.R1, 4, asm.Word),
		// r1 = *(r1+0)
		asm.LoadMem(asm.R1, asm.R1, 0, asm.Word),
		// r3 = r1
		asm.Mov.Reg(asm.R3, asm.R1),
		// r3 += len(buf)
		asm.Add.Imm(asm.R3, int32(len(buf))),
		// if r3 > r2 goto +len(pat)
		asm.JGT.Reg(asm.R3, asm.R2, "out"),
	}
	for i, b := range pat {
		ins = append(ins, asm.StoreImm(asm.R1, int16(i), int64(b), asm.Byte))
	}
	ins = append(ins,
		// return 42
		asm.LoadImm(asm.R0, 42, asm.DWord).WithSymbol("out"),
		asm.Return(),
	)

	if platform.IsWindows {
		// Windows uses an incompatible context for XDP. Pointers are
		// 64 bit.
		// See https://github.com/microsoft/ebpf-for-windows/issues/3873
		// r2 = *(r1+8)
		ins[0] = asm.LoadMem(asm.R2, asm.R1, 8, asm.DWord)
		// r1 = *(r1+0)
		ins[1] = asm.LoadMem(asm.R1, asm.R1, 0, asm.DWord)
	}

	t.Log(ins)

	prog := mustNewProgram(t, &ProgramSpec{
		Name:         "test",
		Type:         XDP,
		Instructions: ins,
		License:      "MIT",
	}, nil)

	p2, err := prog.Clone()
	if err != nil {
		t.Fatal("Can't clone program")
	}
	defer p2.Close()

	prog.Close()
	prog = p2

	out := make([]byte, len(buf))
	ret := mustRun(t, prog, &RunOptions{Data: buf, DataOut: out})
	qt.Assert(t, qt.Equals(ret, 42))
	qt.Assert(t, qt.DeepEquals(out[:len(pat)], pat))
}

func TestProgramRunWithOptions(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.15", "XDP ctx_in/ctx_out")

	buf := internal.EmptyBPFContext
	var prog *Program
	var in, out any
	if platform.IsWindows {
		type winSampleProgramContext struct {
			_           uint64 // data_start (currently leaks kernel pointer)
			_           uint64 // data_end (currently leaks kernel pointer)
			Uint32Data  uint32
			Uint16Data  uint16
			_           uint16
			HelperData1 uint32
			HelperData2 uint32
		}
		prog = createProgram(t, WindowsSample, 0)
		in = &winSampleProgramContext{Uint32Data: 23, HelperData2: 42}
		out = &winSampleProgramContext{Uint32Data: 23, HelperData2: 42}
	} else {
		prog = createProgram(t, XDP, int64(sys.XDP_ABORTED))
		in = &sys.XdpMd{Data: 0, DataEnd: uint32(len(buf))}
		out = &sys.XdpMd{}
	}

	opts := RunOptions{
		Data:       buf,
		Context:    in,
		ContextOut: out,
	}
	ret, err := prog.Run(&opts)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 0 {
		t.Error("Expected return value to be 0, got", ret)
	}

	qt.Assert(t, qt.DeepEquals(out, in))
}

func TestProgramRunRawTracepoint(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.10", "RawTracepoint test run")

	prog := createProgram(t, RawTracepoint, 0)

	ret, err := prog.Run(&RunOptions{})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 0 {
		t.Error("Expected return value to be 0, got", ret)
	}
}

func TestProgramRunEmptyData(t *testing.T) {
	prog := createProgram(t, SocketFilter, 0)
	_, err := prog.Run(nil)
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.ErrorIs(err, unix.EINVAL))
}

func TestProgramBenchmark(t *testing.T) {
	if platform.IsWindows {
		t.Skip("BPF_PROG_TEST_RUN requires providing context on Windows")
	}

	prog := createBasicProgram(t)

	ret, duration, err := prog.Benchmark(internal.EmptyBPFContext, 1, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Error from Benchmark:", err)
	}

	if ret != 2 {
		t.Error("Expected return value 2, got", ret)
	}

	if duration == 0 {
		t.Error("Expected non-zero duration")
	}
}

func TestProgramClose(t *testing.T) {
	prog := createBasicProgram(t)

	if err := prog.Close(); err != nil {
		t.Fatal("Can't close program:", err)
	}
}

func TestProgramPin(t *testing.T) {
	spec := fixupProgramSpec(basicProgramSpec)
	prog := mustNewProgram(t, spec, nil)

	tmp := testutils.TempBPFFS(t)

	path := filepath.Join(tmp, "program")
	if err := prog.Pin(path); err != nil {
		t.Fatal(err)
	}

	pinned := prog.IsPinned()
	qt.Assert(t, qt.IsTrue(pinned))

	prog.Close()

	prog, err := LoadPinnedProgram(path, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	qt.Assert(t, qt.Equals(prog.Type(), spec.Type))

	if haveObjName() == nil {
		qt.Assert(t, qt.Equals(prog.name, "test"))
	} else {
		qt.Assert(t, qt.Equals(prog.name, "program"))
	}

	if !prog.IsPinned() {
		t.Error("Expected IsPinned to be true")
	}
}

func TestProgramUnpin(t *testing.T) {
	prog := createBasicProgram(t)

	tmp := testutils.TempBPFFS(t)

	path := filepath.Join(tmp, "program")
	if err := prog.Pin(path); err != nil {
		t.Fatal(err)
	}

	pinned := prog.IsPinned()
	qt.Assert(t, qt.IsTrue(pinned))

	if err := prog.Unpin(); err != nil {
		t.Fatal("Failed to unpin program:", err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("Pinned program path still exists after unpinning:", err)
	}
}

func TestProgramLoadPinnedWithFlags(t *testing.T) {
	// Introduced in commit 6e71b04a8224.
	testutils.SkipOnOldKernel(t, "4.14", "file_flags in BPF_OBJ_GET")

	prog := createBasicProgram(t)

	tmp := testutils.TempBPFFS(t)

	path := filepath.Join(tmp, "program")
	if err := prog.Pin(path); err != nil {
		t.Fatal(err)
	}

	prog.Close()

	_, err := LoadPinnedProgram(path, &LoadPinOptions{
		Flags: math.MaxUint32,
	})
	testutils.SkipIfNotSupported(t, err)
	if !errors.Is(err, unix.EINVAL) {
		t.Fatal("Invalid flags don't trigger an error:", err)
	}
}

func TestProgramVerifierOutputOnError(t *testing.T) {
	_, err := newProgram(t, &ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.Return(),
		},
		License: "MIT",
	}, nil)
	if err == nil {
		t.Fatal("Expected program to be invalid")
	}

	ve, ok := err.(*VerifierError)
	if !ok {
		t.Fatal("NewProgram does return an unwrapped VerifierError")
	}

	switch {
	case platform.IsLinux:
		if !strings.Contains(ve.Error(), "R0 !read_ok") {
			t.Logf("%+v", ve)
			t.Error("Missing verifier log in error summary")
		}
	case platform.IsWindows:
		if !strings.Contains(ve.Error(), "r0.type == number") {
			t.Logf("%+v", ve)
			t.Error("Missing verifier log in error summary")
		}
	default:
		t.Error("Unsupported platform", runtime.GOOS)
	}
}

func TestProgramKernelVersion(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.20", "KernelVersion")

	_ = mustNewProgram(t, &ProgramSpec{
		Type: Kprobe,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		KernelVersion: 42,
		License:       "MIT",
	}, nil)
}

func TestProgramVerifierLog(t *testing.T) {
	check := func(t *testing.T, err error) {
		t.Helper()

		var ve *internal.VerifierError
		qt.Assert(t, qt.ErrorAs(err, &ve))
		loglen := 0
		for _, line := range ve.Log {
			loglen += len(line)
		}
		qt.Assert(t, qt.IsTrue(loglen > 0))
	}

	// Touch R10 (read-only frame pointer) to reliably force a verifier error.
	invalid := asm.Instructions{
		asm.Mov.Reg(asm.R10, asm.R0),
		asm.Return(),
	}

	valid := asm.Instructions{
		asm.Mov.Imm(asm.R0, 0),
		asm.Return(),
	}

	// Start out with testing against the invalid program.
	spec := &ProgramSpec{
		Type:         SocketFilter,
		License:      "MIT",
		Instructions: invalid,
	}

	// Don't explicitly request a verifier log for an invalid program.
	_, err := newProgram(t, spec, nil)
	check(t, err)

	// Disabling the verifier log should result in a VerifierError without a log.
	_, err = newProgram(t, spec, &ProgramOptions{
		LogDisabled: true,
	})
	var ve *internal.VerifierError
	qt.Assert(t, qt.ErrorAs(err, &ve))
	qt.Assert(t, qt.HasLen(ve.Log, 0))

	// Explicitly request a verifier log for an invalid program.
	_, err = newProgram(t, spec, &ProgramOptions{
		LogLevel: LogLevelInstruction,
	})
	check(t, err)

	// Run tests against a valid program from here on out.
	spec.Instructions = valid

	// Don't request a verifier log, expect the valid program to be created
	// without errors.
	prog := mustNewProgram(t, spec, nil)
	qt.Assert(t, qt.HasLen(prog.VerifierLog, 0))

	// Explicitly request verifier log for a valid program.
	prog = mustNewProgram(t, spec, &ProgramOptions{
		LogLevel: LogLevelInstruction,
	})
	qt.Assert(t, qt.Not(qt.HasLen(prog.VerifierLog, 0)))
}

func TestProgramVerifierLogRetry(t *testing.T) {
	someError := errors.New("not a buffer error")

	t.Run("retry with oversized buffer, no log_true_size", func(t *testing.T) {
		// First load failure, without logging enabled. Retry with logging enabled.
		attr := &sys.ProgLoadAttr{LogLevel: 0, LogSize: 0}
		qt.Assert(t, qt.IsTrue(retryLogAttrs(attr, 0, someError)))
		qt.Assert(t, qt.Equals(attr.LogLevel, LogLevelBranch))
		qt.Assert(t, qt.Equals(attr.LogSize, minVerifierLogSize))

		// Second failure with logging enabled. No buffer error, don't retry.
		qt.Assert(t, qt.IsFalse(retryLogAttrs(attr, 0, someError)))
		qt.Assert(t, qt.Equals(attr.LogLevel, LogLevelBranch))
		qt.Assert(t, qt.Equals(attr.LogSize, minVerifierLogSize))
	})

	t.Run("retry with oversized buffer, with log_true_size", func(t *testing.T) {
		// First load failure, without logging enabled. Retry with larger buffer.
		attr := &sys.ProgLoadAttr{LogLevel: 0, LogSize: 0}
		qt.Assert(t, qt.IsTrue(retryLogAttrs(attr, 0, someError)))

		// Buffer was sufficiently large and log_true_size was set. Don't retry and
		// don't modify LogSize to LogTrueSize.
		attr.LogTrueSize = 123
		qt.Assert(t, qt.IsFalse(retryLogAttrs(attr, 0, someError)))
		qt.Assert(t, qt.Equals(attr.LogSize, minVerifierLogSize))
	})

	t.Run("retry with undersized buffer, no log_true_size", func(t *testing.T) {
		// First load failure, without logging enabled. Retry with larger buffer.
		attr := &sys.ProgLoadAttr{LogLevel: 0, LogSize: 0}
		qt.Assert(t, qt.IsTrue(retryLogAttrs(attr, 0, someError)))

		// Second failure, this time the kernel signals an undersized buffer. Retry
		// with double the size.
		qt.Assert(t, qt.IsTrue(retryLogAttrs(attr, 0, unix.ENOSPC)))
		qt.Assert(t, qt.Equals(attr.LogSize, minVerifierLogSize*2))
	})

	t.Run("retry with undersized buffer, with log_true_size", func(t *testing.T) {
		// First load failure, without logging enabled. Retry with larger buffer.
		attr := &sys.ProgLoadAttr{LogLevel: 0, LogSize: 0}
		qt.Assert(t, qt.IsTrue(retryLogAttrs(attr, 0, someError)))

		// Second failure, the kernel signals undersized buffer and also sets
		// log_true_size. Retry with the exact size required.
		attr.LogTrueSize = 123
		qt.Assert(t, qt.IsTrue(retryLogAttrs(attr, 0, unix.ENOSPC)))
		qt.Assert(t, qt.Equals(attr.LogSize, 123))
	})

	t.Run("grow to maximum buffer size", func(t *testing.T) {
		// Previous loads pushed the log size to (or above) half of the maximum,
		// which would make it overflow on the next retry. Make sure the log size
		// actually hits the maximum so we can bail out.
		attr := &sys.ProgLoadAttr{LogLevel: LogLevelBranch, LogSize: maxVerifierLogSize / 2}
		qt.Assert(t, qt.IsTrue(retryLogAttrs(attr, 0, unix.ENOSPC)))
		qt.Assert(t, qt.Equals(attr.LogSize, maxVerifierLogSize))

		// Don't retry if the buffer is already at the maximum size, no matter
		// the return code.
		qt.Assert(t, qt.IsFalse(retryLogAttrs(attr, 0, someError)))
		qt.Assert(t, qt.IsFalse(retryLogAttrs(attr, 0, unix.ENOSPC)))
	})

	t.Run("start at maximum buffer size", func(t *testing.T) {
		// The user requested a log buffer exceeding the maximum size, but no log
		// level. Retry with the maximum size and default log level.
		attr := &sys.ProgLoadAttr{LogLevel: 0, LogSize: 0}
		qt.Assert(t, qt.IsTrue(retryLogAttrs(attr, math.MaxUint32, unix.EINVAL)))
		qt.Assert(t, qt.Equals(attr.LogLevel, LogLevelBranch))
		qt.Assert(t, qt.Equals(attr.LogSize, maxVerifierLogSize))

		// Log still doesn't fit maximum-size buffer. Don't retry.
		qt.Assert(t, qt.IsFalse(retryLogAttrs(attr, 0, unix.ENOSPC)))
	})

	t.Run("ensure growth terminates within max attempts", func(t *testing.T) {
		attr := &sys.ProgLoadAttr{LogLevel: 0, LogSize: 0}
		var terminated bool
		for i := 1; i <= maxVerifierAttempts; i++ {
			if !retryLogAttrs(attr, 0, syscall.ENOSPC) {
				terminated = true
			}
		}
		qt.Assert(t, qt.IsTrue(terminated))
	})
}

func TestProgramWithUnsatisfiedMap(t *testing.T) {
	coll, err := LoadCollectionSpec("testdata/loader-el.elf")
	if err != nil {
		t.Fatal(err)
	}

	// The program will have at least one map reference.
	progSpec := coll.Programs["xdp_prog"]
	progSpec.ByteOrder = nil

	_, err = newProgram(t, progSpec, nil)
	if !errors.Is(err, asm.ErrUnsatisfiedMapReference) {
		t.Fatal("Expected an error wrapping asm.ErrUnsatisfiedMapReference, got", err)
	}
	t.Log(err)
}

func TestProgramName(t *testing.T) {
	testutils.SkipIfNotSupported(t, haveObjName())

	prog := mustNewProgram(t, &ProgramSpec{
		Name: "test*123",
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 1, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	}, nil)

	var info sys.ProgInfo
	if err := sys.ObjInfo(prog.fd, &info); err != nil {
		t.Fatal(err)
	}

	name := unix.ByteSliceToString(info.Name[:])
	qt.Assert(t, qt.Equals(name, "test123"))
}

func TestProgramCloneNil(t *testing.T) {
	p, err := (*Program)(nil).Clone()
	if err != nil {
		t.Fatal(err)
	}

	if p != nil {
		t.Fatal("Cloning a nil Program doesn't return nil")
	}
}

func TestProgramMarshaling(t *testing.T) {
	const idx = uint32(0)

	arr := createMap(t, ProgramArray, 1)
	defer arr.Close()

	if err := arr.Put(idx, (*Program)(nil)); err == nil {
		t.Fatal("Put accepted a nil Program")
	}

	prog := createBasicProgram(t)

	if err := arr.Put(idx, prog); err != nil {
		t.Fatal("Can't put program:", err)
	}

	if err := arr.Lookup(idx, Program{}); err == nil {
		t.Fatal("Lookup accepts non-pointer Program")
	}

	var prog2 *Program
	defer prog2.Close()

	if err := arr.Lookup(idx, prog2); err == nil {
		t.Fatal("Get accepts *Program")
	}

	testutils.SkipOnOldKernel(t, "4.12", "lookup for ProgramArray")

	if err := arr.Lookup(idx, &prog2); err != nil {
		t.Fatal("Can't unmarshal program:", err)
	}
	defer prog2.Close()

	if prog2 == nil {
		t.Fatal("Unmarshalling set program to nil")
	}
}

func TestProgramFromFD(t *testing.T) {
	spec := fixupProgramSpec(basicProgramSpec)
	prog := mustNewProgram(t, spec, nil)

	// If you're thinking about copying this, don't. Use
	// Clone() instead.
	prog2, err := NewProgramFromFD(testutils.DupFD(t, prog.FD()))
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer prog2.Close()

	// Name and type are supposed to be copied from program info.
	if haveObjName() == nil && prog2.name != "test" {
		t.Errorf("Expected program to have name test, got '%s'", prog2.name)
	}

	qt.Assert(t, qt.Equals(prog2.Type(), spec.Type))
}

func TestHaveProgTestRun(t *testing.T) {
	testutils.CheckFeatureTest(t, haveProgRun)
}

func TestProgramGetNextID(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.13", "bpf_prog_get_next_id")

	// Ensure there is at least one program loaded
	_ = createBasicProgram(t)

	// As there can be multiple eBPF programs, we loop over all of them and
	// make sure, the IDs increase and the last call will return ErrNotExist
	last := ProgramID(0)
	for {
		next, err := ProgramGetNextID(last)
		if errors.Is(err, os.ErrNotExist) {
			if last == 0 {
				t.Fatal("Got ErrNotExist on the first iteration")
			}
			break
		}
		if err != nil {
			t.Fatal("Unexpected error:", err)
		}
		if next <= last {
			t.Fatalf("Expected next ID (%d) to be higher than the last ID (%d)", next, last)
		}
		last = next
	}
}

func TestNewProgramFromID(t *testing.T) {
	prog := createBasicProgram(t)

	info, err := prog.Info()
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal("Could not get program info:", err)
	}

	id, ok := info.ID()
	if !ok {
		t.Skip("Program ID not supported")
	}

	prog2, err := NewProgramFromID(id)
	if err != nil {
		t.Fatalf("Can't get FD for program ID %d: %v", id, err)
	}
	prog2.Close()

	// As there can be multiple programs, we use max(uint32) as ProgramID to trigger an expected error.
	_, err = NewProgramFromID(ProgramID(math.MaxUint32))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Expected ErrNotExist, got:", err)
	}
}

func TestProgramRejectIncorrectByteOrder(t *testing.T) {
	spec := basicProgramSpec.Copy()

	spec.ByteOrder = binary.BigEndian
	if spec.ByteOrder == internal.NativeEndian {
		spec.ByteOrder = binary.LittleEndian
	}

	_, err := newProgram(t, spec, nil)
	if err == nil {
		t.Error("Incorrect ByteOrder should be rejected at load time")
	}
}

// This uses unkeyed fields on purpose to force setting a non-zero value when
// a new field is added.
func TestProgramSpecCopy(t *testing.T) {
	a := &ProgramSpec{
		"test",
		1,
		1,
		1,
		"attach",
		nil, // Can't copy Program
		"section",
		asm.Instructions{
			asm.Return(),
		},
		1,
		"license",
		1,
		binary.LittleEndian,
	}

	qt.Check(t, qt.IsNil((*ProgramSpec)(nil).Copy()))
	qt.Assert(t, testutils.IsDeepCopy(a.Copy(), a))
}

func TestProgramSpecCompatible(t *testing.T) {
	arr := createMap(t, Array, 2)

	spec := &ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, -1, asm.DWord),
			asm.LoadMapPtr(asm.R1, arr.FD()),
			asm.Mov.Imm32(asm.R0, 0),
			asm.Return(),
		},
		License: "MIT",
	}

	prog := mustNewProgram(t, spec, nil)

	info, err := prog.Info()
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))

	err = spec.Compatible(info)
	testutils.SkipIfNotSupportedOnOS(t, err)
	qt.Assert(t, qt.IsNil(err))
}

func TestProgramAttachToKernel(t *testing.T) {
	// See https://github.com/torvalds/linux/commit/290248a5b7d829871b3ea3c62578613a580a1744
	testutils.SkipOnOldKernel(t, "5.5", "attach_btf_id")

	tests := []struct {
		attachTo    string
		programType ProgramType
		attachType  AttachType
		flags       uint32
	}{
		{
			attachTo:    "task_getpgid",
			programType: LSM,
			attachType:  AttachLSMMac,
		},
		{
			attachTo:    "inet_dgram_connect",
			programType: Tracing,
			attachType:  AttachTraceFEntry,
		},
		{
			attachTo:    "inet_dgram_connect",
			programType: Tracing,
			attachType:  AttachTraceFExit,
		},
		{
			attachTo:    "bpf_modify_return_test",
			programType: Tracing,
			attachType:  AttachModifyReturn,
		},
		{
			attachTo:    "kfree_skb",
			programType: Tracing,
			attachType:  AttachTraceRawTp,
		},
		{
			attachTo:    "bpf_testmod_test_read",
			programType: Tracing,
			attachType:  AttachTraceFEntry,
		},
		{
			attachTo:    "bpf_testmod_test_read",
			programType: Tracing,
			attachType:  AttachTraceFExit,
		},
		{
			attachTo:    "bpf_testmod_test_read",
			programType: Tracing,
			attachType:  AttachModifyReturn,
		},
		{
			attachTo:    "bpf_testmod_test_read",
			programType: Tracing,
			attachType:  AttachTraceRawTp,
		},
	}
	for _, test := range tests {
		name := fmt.Sprintf("%s:%s", test.attachType, test.attachTo)
		t.Run(name, func(t *testing.T) {
			if strings.HasPrefix(test.attachTo, "bpf_testmod_") {
				requireTestmod(t)
			}

			_ = mustNewProgram(t, &ProgramSpec{
				AttachTo:   test.attachTo,
				AttachType: test.attachType,
				Instructions: asm.Instructions{
					asm.LoadImm(asm.R0, 0, asm.DWord),
					asm.Return(),
				},
				License: "GPL",
				Type:    test.programType,
				Flags:   test.flags,
			}, nil)
		})
	}
}

func TestProgramKernelTypes(t *testing.T) {
	if _, err := os.Stat("/sys/kernel/btf/vmlinux"); os.IsNotExist(err) {
		t.Skip("/sys/kernel/btf/vmlinux not present")
	}

	btfSpec, err := btf.LoadSpec("/sys/kernel/btf/vmlinux")
	if err != nil {
		t.Fatal(err)
	}

	_, err = newProgram(t, &ProgramSpec{
		Type:       Tracing,
		AttachType: AttachTraceIter,
		AttachTo:   "bpf_map",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "MIT",
	}, &ProgramOptions{
		KernelTypes: btfSpec,
	})
	testutils.SkipIfNotSupported(t, err)
	qt.Assert(t, qt.IsNil(err))
}

func TestProgramBindMap(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.10", "BPF_PROG_BIND_MAP")

	arr := createMap(t, Array, 2)
	prog := createBasicProgram(t)

	// The attached map does not contain BTF information. So
	// the metadata part of the program will be empty. This
	// test just makes sure that we can bind a map to a program.
	if err := prog.BindMap(arr); err != nil {
		t.Errorf("Failed to bind map to program: %v", err)
	}
}

func TestProgramInstructions(t *testing.T) {
	name := "test_prog"
	spec := &ProgramSpec{
		Type: SocketFilter,
		Name: name,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, -1, asm.DWord).WithSymbol(name),
			asm.Return(),
		},
		License: "MIT",
	}

	prog := mustNewProgram(t, spec, nil)

	pi, err := prog.Info()
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	if platform.IsWindows {
		t.Skip("prog.Info() does not return a valid Tag on Windows")
	}

	ok, err := spec.Instructions.HasTag(pi.Tag, internal.NativeEndian)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(ok), qt.Commentf("ProgramSpec tag differs from xlated instructions"))
}

func TestProgramLoadErrors(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.10", "stable verifier log output")

	spec, err := LoadCollectionSpec(testutils.NativeFile(t, "testdata/errors-%s.elf"))
	qt.Assert(t, qt.IsNil(err))

	var b btf.Builder
	raw, err := b.Marshal(nil, nil)
	qt.Assert(t, qt.IsNil(err))
	empty, err := btf.LoadSpecFromReader(bytes.NewReader(raw))
	qt.Assert(t, qt.IsNil(err))

	for _, test := range []struct {
		name string
		want error
	}{
		{"poisoned_single", errBadRelocation},
		{"poisoned_double", errBadRelocation},
		{"poisoned_kfunc", errUnknownKfunc},
	} {
		progSpec := spec.Programs[test.name]
		qt.Assert(t, qt.IsNotNil(progSpec))

		t.Run(test.name, func(t *testing.T) {
			t.Log(progSpec.Instructions)
			_, err := newProgram(t, progSpec, &ProgramOptions{
				KernelTypes: empty,
			})
			testutils.SkipIfNotSupported(t, err)

			var ve *VerifierError
			qt.Assert(t, qt.ErrorAs(err, &ve))
			t.Logf("%-5v", ve)

			qt.Assert(t, qt.ErrorIs(err, test.want))
		})
	}
}

func TestProgramTargetsKernelModule(t *testing.T) {
	ps := ProgramSpec{Type: Kprobe}
	qt.Assert(t, qt.IsFalse(ps.targetsKernelModule()))

	ps.AttachTo = "bpf_testmod_test_read"
	qt.Assert(t, qt.IsTrue(ps.targetsKernelModule()))
}

func TestProgramLoadBoundToDevice(t *testing.T) {
	testutils.SkipOnOldKernel(t, "6.3", "device-bound XDP programs")

	ins := asm.Instructions{
		asm.LoadImm(asm.R0, 2, asm.DWord).WithSymbol("out"),
		asm.Return(),
	}

	_, err := NewProgram(&ProgramSpec{
		Type:         XDP,
		Ifindex:      math.MaxUint32,
		AttachType:   AttachXDP,
		Instructions: ins,
		Flags:        sys.BPF_F_XDP_DEV_BOUND_ONLY,
		License:      "MIT",
	})
	testutils.SkipIfNotSupportedOnOS(t, err)

	// Binding to loopback leads to crashes, yet is only explicitly disallowed
	// since 3595599fa836 ("net: xdp: Disallow attaching device-bound programs in
	// generic mode"). This only landed in 6.14 and returns EOPNOTSUPP.
	//
	// However, since attaching to loopback quietly succeeds on older kernels, use
	// a non-existent ifindex to trigger EINVAL on all kernels. Without specifying
	// ifindex, loading the program succeeds if the kernel knows the
	// DEV_BOUND_ONLY flag.
	qt.Assert(t, qt.ErrorIs(err, unix.EINVAL))
}

func TestProgramWithToken(t *testing.T) {
	t.Run("no-cmd", func(t *testing.T) {
		if testutils.RunWithToken(t, testutils.Delegated{
			Cmds:        []sys.Cmd{},
			Progs:       []sys.ProgType{sys.BPF_PROG_TYPE_SOCKET_FILTER},
			AttachTypes: []sys.AttachType{sys.BPF_CGROUP_INET_INGRESS},
		}) {
			return
		}

		_, err := newProgram(t, basicProgramSpec, nil)
		qt.Assert(t, qt.ErrorIs(err, unix.EPERM))
	})

	t.Run("no-prog", func(t *testing.T) {
		if testutils.RunWithToken(t, testutils.Delegated{
			Cmds:        []sys.Cmd{sys.BPF_PROG_LOAD},
			Progs:       []sys.ProgType{},
			AttachTypes: []sys.AttachType{sys.BPF_CGROUP_INET_INGRESS},
		}) {
			return
		}

		_, err := newProgram(t, basicProgramSpec, nil)
		qt.Assert(t, qt.ErrorIs(err, unix.EPERM))
	})

	t.Run("no-attach-type", func(t *testing.T) {
		if testutils.RunWithToken(t, testutils.Delegated{
			Cmds:        []sys.Cmd{sys.BPF_PROG_LOAD},
			Progs:       []sys.ProgType{sys.BPF_PROG_TYPE_SOCKET_FILTER},
			AttachTypes: []sys.AttachType{},
		}) {
			return
		}

		_, err := newProgram(t, basicProgramSpec, nil)
		qt.Assert(t, qt.ErrorIs(err, unix.EPERM))
	})

	t.Run("success", func(t *testing.T) {
		if testutils.RunWithToken(t, testutils.Delegated{
			Cmds:        []sys.Cmd{sys.BPF_PROG_LOAD},
			Progs:       []sys.ProgType{sys.BPF_PROG_TYPE_SOCKET_FILTER},
			AttachTypes: []sys.AttachType{sys.BPF_CGROUP_INET_INGRESS},
		}) {
			return
		}

		_, err := newProgram(t, basicProgramSpec, nil)
		qt.Assert(t, qt.IsNil(err))
	})
}

func BenchmarkNewProgram(b *testing.B) {
	testutils.SkipOnOldKernel(b, "5.18", "kfunc support")
	spec, err := LoadCollectionSpec(testutils.NativeFile(b, "testdata/kfunc-%s.elf"))
	qt.Assert(b, qt.IsNil(err))

	b.ReportAllocs()

	for b.Loop() {
		_, err := NewProgram(spec.Programs["benchmark"])
		if !errors.Is(err, unix.EACCES) {
			b.Fatal("Unexpected error:", err)
		}
	}
}

// Print the full verifier log when loading a program fails.
func ExampleVerifierError_retrieveFullLog() {
	_, err := NewProgram(&ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			// Missing Return
		},
		License: "MIT",
	})

	var ve *VerifierError
	if errors.As(err, &ve) {
		// Using %+v will print the whole verifier error, not just the last
		// few lines.
		fmt.Printf("Verifier error: %+v\n", ve)
	}
}

// VerifierLog understands a variety of formatting flags.
func ExampleVerifierError() {
	err := internal.ErrorWithLog(
		"catastrophe",
		syscall.ENOSPC,
		[]byte("first\nsecond\nthird"),
	)

	fmt.Printf("With %%s: %s\n", err)
	fmt.Printf("All log lines: %+v\n", err)
	fmt.Printf("First line: %+1v\n", err)
	fmt.Printf("Last two lines: %-2v\n", err)

	// Output: With %s: catastrophe: no space left on device: third (2 line(s) omitted)
	// All log lines: catastrophe: no space left on device:
	// 	first
	// 	second
	// 	third
	// First line: catastrophe: no space left on device:
	// 	first
	// 	(2 line(s) omitted)
	// Last two lines: catastrophe: no space left on device:
	// 	(1 line(s) omitted)
	// 	second
	// 	third
}

// Use NewProgramWithOptions if you'd like to get the verifier output
// for a program, or if you want to change the buffer size used when
// generating error messages.
func ExampleProgram_retrieveVerifierLog() {
	spec := &ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	}

	prog, err := NewProgramWithOptions(spec, ProgramOptions{
		LogLevel: LogLevelInstruction,
	})
	if err != nil {
		panic(err)
	}
	defer prog.Close()

	fmt.Println("The verifier output is:")
	fmt.Println(prog.VerifierLog)
}

// It's possible to read a program directly from a ProgramArray.
func ExampleProgram_unmarshalFromMap() {
	progArray, err := LoadPinnedMap("/path/to/map", nil)
	if err != nil {
		panic(err)
	}
	defer progArray.Close()

	// Load a single program
	var prog *Program
	if err := progArray.Lookup(uint32(0), &prog); err != nil {
		panic(err)
	}
	defer prog.Close()

	fmt.Println("first prog:", prog)

	// Iterate all programs
	var (
		key     uint32
		entries = progArray.Iterate()
	)

	for entries.Next(&key, &prog) {
		fmt.Println(key, "is", prog)
	}

	if err := entries.Err(); err != nil {
		panic(err)
	}
}

func ExampleProgramSpec_Compatible() {
	spec := &ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	}

	prog, _ := NewProgram(spec)
	info, _ := prog.Info()

	if err := spec.Compatible(info); err != nil {
		fmt.Printf("The programs are incompatible: %s\n", err)
	} else {
		fmt.Println("The programs are compatible")
	}
}
