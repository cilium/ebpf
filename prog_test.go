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

	ret, out, err := prog.Test(buf)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	if ret != 42 {
		t.Error("Expected return value to be 42, got", ret)
	}

	if !bytes.Equal(out[:len(pat)], pat) {
		t.Errorf("Expected %v, got %v", pat, out)
	}
}

func TestProgramRunWithOptions(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.15", "XDP ctx_in/ctx_out")

	prog := createProgram(t, XDP, int64(sys.XDP_ABORTED))

	buf := internal.EmptyBPFContext
	var in, out any
	if platform.IsWindows {
		type winXdpMd struct {
			Data, DataEnd, DataMeta uint64
			Ifindex                 uint32
		}
		in = &winXdpMd{Data: 0, DataEnd: uint64(len(buf))}
		out = &winXdpMd{}
	} else {
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
	if err := haveObjName(); err != nil {
		t.Skip(err)
	}

	prog := createBasicProgram(t)

	var info sys.ProgInfo
	if err := sys.ObjInfo(prog.fd, &info); err != nil {
		t.Fatal(err)
	}

	if name := unix.ByteSliceToString(info.Name[:]); name != "test" {
		t.Errorf("Name is not test, got '%s'", name)
	}
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

func TestProgramSpecCopy(t *testing.T) {
	a := &ProgramSpec{
		"test",
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

func TestProgramSpecTag(t *testing.T) {
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
	if err != nil {
		t.Fatal(err)
	}

	tag, err := spec.Tag()
	if err != nil {
		t.Fatal("Can't calculate tag:", err)
	}

	if info.Tag != "" && tag != info.Tag {
		t.Errorf("Calculated tag %s doesn't match kernel tag %s", tag, info.Tag)
	}
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

	insns, err := pi.Instructions()
	testutils.SkipIfNotSupportedOnOS(t, err)
	if err != nil {
		t.Fatal(err)
	}

	tag, err := spec.Tag()
	if err != nil {
		t.Fatal(err)
	}

	tagXlated, err := insns.Tag(internal.NativeEndian)
	if err != nil {
		t.Fatal(err)
	}

	if tag != tagXlated {
		t.Fatalf("tag %s differs from xlated instructions tag %s", tag, tagXlated)
	}
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

func TestProgramAttachToKernelModule(t *testing.T) {
	requireTestmod(t)

	ps := ProgramSpec{AttachTo: "bpf_testmod_test_read", Type: Tracing, AttachType: AttachTraceFEntry}
	mod, err := ps.kernelModule()
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(mod, "bpf_testmod"))
}

func BenchmarkNewProgram(b *testing.B) {
	testutils.SkipOnOldKernel(b, "5.18", "kfunc support")
	spec, err := LoadCollectionSpec(testutils.NativeFile(b, "testdata/kfunc-%s.elf"))
	qt.Assert(b, qt.IsNil(err))

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
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

func ExampleProgramSpec_Tag() {
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
	tag, _ := spec.Tag()

	if info.Tag != tag {
		fmt.Printf("The tags don't match: %s != %s\n", info.Tag, tag)
	} else {
		fmt.Println("The programs are identical, tag is", tag)
	}
}
