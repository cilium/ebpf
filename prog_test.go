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
	"time"

	qt "github.com/frankban/quicktest"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"
)

func TestProgramRun(t *testing.T) {
	pat := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	buf := make([]byte, 14)

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
		asm.LoadImm(asm.R0, 42, asm.DWord).Sym("out"),
		asm.Return(),
	)

	t.Log(ins)

	prog, err := NewProgram(&ProgramSpec{
		Name:         "test",
		Type:         XDP,
		Instructions: ins,
		License:      "MIT",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

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

func TestProgramBenchmark(t *testing.T) {
	prog := createSocketFilter(t)
	defer prog.Close()

	ret, duration, err := prog.Benchmark(make([]byte, 14), 1, nil)
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

func TestProgramTestRunInterrupt(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.0", "EINTR from BPF_PROG_TEST_RUN")

	prog := createSocketFilter(t)
	defer prog.Close()

	var (
		tgid    = unix.Getpid()
		tidChan = make(chan int, 1)
		exit    = make(chan struct{})
		errs    = make(chan error, 1)
		timeout = time.After(5 * time.Second)
	)

	defer close(exit)

	go func() {
		runtime.LockOSThread()
		defer func() {
			// Wait for the test to allow us to unlock the OS thread, to
			// ensure that we don't send SIGUSR1 to the wrong thread.
			<-exit
			runtime.UnlockOSThread()
		}()

		tidChan <- unix.Gettid()

		// Block this thread in the BPF syscall, so that we can
		// trigger EINTR by sending a signal.
		_, _, _, err := prog.testRun(make([]byte, 14), math.MaxInt32, func() {
			// We don't know how long finishing the
			// test run would take, so flag that we've seen
			// an interruption and abort the goroutine.
			close(errs)
			runtime.Goexit()
		})

		errs <- err
	}()

	tid := <-tidChan
	for {
		err := unix.Tgkill(tgid, tid, syscall.SIGUSR1)
		if err != nil {
			t.Fatal("Can't send signal to goroutine thread:", err)
		}

		select {
		case err, ok := <-errs:
			if !ok {
				return
			}

			testutils.SkipIfNotSupported(t, err)
			if err == nil {
				t.Fatal("testRun wasn't interrupted")
			}

			t.Fatal("testRun returned an error:", err)

		case <-timeout:
			t.Fatal("Timed out trying to interrupt the goroutine")

		default:
		}
	}
}

func TestProgramClose(t *testing.T) {
	prog := createSocketFilter(t)

	if err := prog.Close(); err != nil {
		t.Fatal("Can't close program:", err)
	}
}

func TestProgramPin(t *testing.T) {
	prog := createSocketFilter(t)
	c := qt.New(t)
	defer prog.Close()

	tmp := testutils.TempBPFFS(t)

	path := filepath.Join(tmp, "program")
	if err := prog.Pin(path); err != nil {
		t.Fatal(err)
	}

	pinned := prog.IsPinned()
	c.Assert(pinned, qt.Equals, true)

	prog.Close()

	prog, err := LoadPinnedProgram(path, nil)
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	if prog.Type() != SocketFilter {
		t.Error("Expected pinned program to have type SocketFilter, but got", prog.Type())
	}

	if !prog.IsPinned() {
		t.Error("Expected IsPinned to be true")
	}
}

func TestProgramUnpin(t *testing.T) {
	prog := createSocketFilter(t)
	c := qt.New(t)
	defer prog.Close()

	tmp := testutils.TempBPFFS(t)

	path := filepath.Join(tmp, "program")
	if err := prog.Pin(path); err != nil {
		t.Fatal(err)
	}

	pinned := prog.IsPinned()
	c.Assert(pinned, qt.Equals, true)

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

	prog := createSocketFilter(t)
	defer prog.Close()

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
	_, err := NewProgram(&ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.Return(),
		},
		License: "MIT",
	})
	if err == nil {
		t.Fatal("Expected program to be invalid")
	}

	if !strings.Contains(err.Error(), "exit") {
		t.Error("No verifier output in error message")
	}
}

func TestProgramKernelVersion(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.20", "KernelVersion")
	prog, err := NewProgram(&ProgramSpec{
		Type: Kprobe,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		KernelVersion: 42,
		License:       "MIT",
	})
	if err != nil {
		t.Fatal("Could not load Kprobe program")
	}
	defer prog.Close()
}

func TestProgramVerifierOutput(t *testing.T) {
	prog, err := NewProgramWithOptions(socketFilterSpec, ProgramOptions{
		LogLevel: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	if prog.VerifierLog == "" {
		t.Error("Expected VerifierLog to be present")
	}

	// Issue 64
	_, err = NewProgramWithOptions(&ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.Mov.Reg(asm.R0, asm.R1),
		},
		License: "MIT",
	}, ProgramOptions{
		LogLevel: 2,
	})

	if err == nil {
		t.Fatal("Expected an error from invalid program")
	}

	var ve *internal.VerifierError
	if !errors.As(err, &ve) {
		t.Error("Error is not a VerifierError")
	}
}

func TestProgramWithUnsatisfiedReference(t *testing.T) {
	coll, err := LoadCollectionSpec("testdata/loader-el.elf")
	if err != nil {
		t.Fatal(err)
	}

	// The program will have at least one map reference.
	progSpec := coll.Programs["xdp_prog"]
	progSpec.ByteOrder = nil

	_, err = NewProgram(progSpec)
	if !errors.Is(err, errUnsatisfiedReference) {
		t.Fatal("Expected an error wrapping errUnsatisfiedReference, got", err)
	}
	t.Log(err)
}

func TestProgramName(t *testing.T) {
	if err := haveObjName(); err != nil {
		t.Skip(err)
	}

	prog := createSocketFilter(t)
	defer prog.Close()

	info, err := bpfGetProgInfoByFD(prog.fd, nil)
	if err != nil {
		t.Fatal(err)
	}

	if name := internal.CString(info.name[:]); name != "test" {
		t.Errorf("Name is not test, got '%s'", name)
	}
}

func TestSanitizeName(t *testing.T) {
	for input, want := range map[string]string{
		"test":     "test",
		"t-est":    "test",
		"t_est":    "t_est",
		"hörnchen": "hrnchen",
	} {
		if have := SanitizeName(input, -1); have != want {
			t.Errorf("Wanted '%s' got '%s'", want, have)
		}
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

	arr := createProgramArray(t)
	defer arr.Close()

	prog, err := NewProgram(&ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

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

	if prog2 == nil {
		t.Fatal("Unmarshalling set program to nil")
	}
}

func TestProgramFromFD(t *testing.T) {
	prog, err := NewProgram(&ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	// If you're thinking about copying this, don't. Use
	// Clone() instead.
	prog2, err := NewProgramFromFD(prog.FD())
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	// Both programs refer to the same fd now. Closing either of them will
	// release the fd to the OS, which then might re-use that fd for another
	// test. Once we close the second map we might close the re-used fd
	// inadvertently, leading to spurious test failures.
	// To avoid this we have to "leak" one of the programs.
	prog2.fd.Forget()
}

func TestHaveProgTestRun(t *testing.T) {
	testutils.CheckFeatureTest(t, haveProgTestRun)
}

func TestProgramGetNextID(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.13", "bpf_prog_get_next_id")
	var next ProgramID

	prog, err := NewProgram(&ProgramSpec{
		Type: SkSKB,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	if next, err = ProgramGetNextID(ProgramID(0)); err != nil {
		t.Fatal("Can't get next ID:", err)
	}
	if next == ProgramID(0) {
		t.Fatal("Expected next ID other than 0")
	}

	// As there can be multiple eBPF programs, we loop over all of them and
	// make sure, the IDs increase and the last call will return ErrNotExist
	for {
		last := next
		if next, err = ProgramGetNextID(last); err != nil {
			if !errors.Is(err, ErrNotExist) {
				t.Fatal("Expected ErrNotExist, got:", err)
			}
			break
		}
		if next <= last {
			t.Fatalf("Expected next ID (%d) to be higher than the last ID (%d)", next, last)
		}
	}
}

func TestNewProgramFromID(t *testing.T) {
	testutils.SkipOnOldKernel(t, "4.13", "bpf_prog_get_fd_by_id")

	prog, err := NewProgram(&ProgramSpec{
		Type: SkSKB,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()
	var next ProgramID

	next, err = prog.ID()
	if err != nil {
		t.Fatal("Could not get ID of program:", err)
	}

	if _, err = NewProgramFromID(next); err != nil {
		t.Fatalf("Can't get FD for program ID %d: %v", uint32(next), err)
	}

	// As there can be multiple programs, we use max(uint32) as ProgramID to trigger an expected error.
	_, err = NewProgramFromID(ProgramID(math.MaxUint32))
	if !errors.Is(err, ErrNotExist) {
		t.Fatal("Expected ErrNotExist, got:", err)
	}
}

func TestProgramRejectIncorrectByteOrder(t *testing.T) {
	spec := socketFilterSpec.Copy()

	spec.ByteOrder = binary.BigEndian
	if internal.NativeEndian == binary.BigEndian {
		spec.ByteOrder = binary.LittleEndian
	}

	_, err := NewProgram(spec)
	if err == nil {
		t.Error("Incorrect ByteOrder should be rejected at load time")
	}
}

func TestProgramSpecTag(t *testing.T) {
	arr := createArray(t)
	defer arr.Close()

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

	prog, err := NewProgram(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer prog.Close()

	info, err := prog.Info()
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}

	tag, err := spec.Tag()
	if err != nil {
		t.Fatal("Can't calculate tag:", err)
	}

	if tag != info.Tag {
		t.Errorf("Calculated tag %s doesn't match kernel tag %s", tag, info.Tag)
	}
}

func TestProgramTypeLSM(t *testing.T) {
	lsmTests := []struct {
		attachFn    string
		flags       uint32
		expectedErr bool
	}{
		{
			attachFn: "task_getpgid",
		},
		{
			attachFn:    "task_setnice",
			flags:       unix.BPF_F_SLEEPABLE,
			expectedErr: true,
		},
		{
			attachFn: "file_open",
			flags:    unix.BPF_F_SLEEPABLE,
		},
	}
	for _, tt := range lsmTests {
		t.Run(tt.attachFn, func(t *testing.T) {
			prog, err := NewProgram(&ProgramSpec{
				AttachTo:   tt.attachFn,
				AttachType: AttachLSMMac,
				Instructions: asm.Instructions{
					asm.LoadImm(asm.R0, 0, asm.DWord),
					asm.Return(),
				},
				License: "GPL",
				Type:    LSM,
				Flags:   tt.flags,
			})
			testutils.SkipIfNotSupported(t, err)

			if tt.flags&unix.BPF_F_SLEEPABLE != 0 {
				testutils.SkipOnOldKernel(t, "5.11", "BPF_F_SLEEPABLE for LSM progs")
			}
			if tt.expectedErr && err == nil {
				t.Errorf("Test case '%s': expected error", tt.attachFn)
			}
			if !tt.expectedErr && err != nil {
				t.Errorf("Test case '%s': expected success", tt.attachFn)
			}
			prog.Close()
		})
	}
}

func TestProgramTargetBTF(t *testing.T) {
	// Load a file that contains valid BTF, but doesn't contain the types
	// we need for bpf_iter.
	fh, err := os.Open("testdata/invalid_btf_map_init-el.elf")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()

	reader := &testReaderAt{file: fh}

	prog, err := NewProgramWithOptions(&ProgramSpec{
		Type:       Tracing,
		AttachType: AttachTraceIter,
		AttachTo:   "bpf_map",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
		License: "MIT",
	}, ProgramOptions{
		TargetBTF: reader,
	})
	if err == nil {
		prog.Close()
	}
	if !errors.Is(err, ErrNotSupported) {
		t.Error("Expected ErrNotSupported, got", err)
	}
	if !reader.read {
		t.Error("TargetBTF is not read")
	}
}

type testReaderAt struct {
	file *os.File
	read bool
}

func (ra *testReaderAt) ReadAt(p []byte, off int64) (int, error) {
	ra.read = true
	return ra.file.ReadAt(p, off)
}

func createProgramArray(t *testing.T) *Map {
	t.Helper()

	arr, err := NewMap(&MapSpec{
		Type:       ProgramArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	return arr
}

var socketFilterSpec = &ProgramSpec{
	Name: "test",
	Type: SocketFilter,
	Instructions: asm.Instructions{
		asm.LoadImm(asm.R0, 2, asm.DWord),
		asm.Return(),
	},
	License: "MIT",
}

func createSocketFilter(t *testing.T) *Program {
	t.Helper()

	prog, err := NewProgram(socketFilterSpec)
	if err != nil {
		t.Fatal(err)
	}

	return prog
}

// Use NewProgramWithOptions if you'd like to get the verifier output
// for a program, or if you want to change the buffer size used when
// generating error messages.
func ExampleNewProgramWithOptions() {
	spec := &ProgramSpec{
		Type: SocketFilter,
		Instructions: asm.Instructions{
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
		License: "MIT",
	}

	prog, err := NewProgramWithOptions(spec, ProgramOptions{
		LogLevel: 2,
		LogSize:  1024,
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
