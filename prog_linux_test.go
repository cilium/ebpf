package ebpf

import (
	"fmt"
	"math"
	"runtime"
	"slices"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"
)

func TestProgramTestRunInterrupt(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.0", "EINTR from BPF_PROG_TEST_RUN")

	prog := createBasicProgram(t)

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
		opts := RunOptions{
			Data:   internal.EmptyBPFContext,
			Repeat: math.MaxInt32,
			Reset: func() {
				// We don't know how long finishing the
				// test run would take, so flag that we've seen
				// an interruption and abort the goroutine.
				close(errs)
				runtime.Goexit()
			},
		}
		_, _, err := prog.run(&opts)

		errs <- err
	}()

	tid := <-tidChan
	for {
		err := unix.Tgkill(tgid, tid, unix.SIGUSR1)
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

func TestProgramVerifierLogLinux(t *testing.T) {
	check := func(t *testing.T, err error) {
		t.Helper()

		var ve *internal.VerifierError
		qt.Assert(t, qt.ErrorAs(err, &ve))

		loglen := len(fmt.Sprintf("%+v", ve))
		qt.Assert(t, qt.IsTrue(loglen > minVerifierLogSize),
			qt.Commentf("Log buffer didn't grow past minimum, got %d bytes", loglen))
	}

	// Generate a base program of sufficient size whose verifier log does not fit
	// in the minimum buffer size. Stay under 4096 insn limit of older kernels.
	var base asm.Instructions
	for i := 0; i < 4093; i++ {
		base = append(base, asm.Mov.Reg(asm.R0, asm.R1))
	}

	// Touch R10 (read-only frame pointer) to reliably force a verifier error.
	invalid := slices.Clone(base)
	invalid = append(invalid, asm.Mov.Reg(asm.R10, asm.R0))
	invalid = append(invalid, asm.Return())

	valid := slices.Clone(base)
	valid = append(valid, asm.Return())

	// Start out with testing against the invalid program.
	spec := &ProgramSpec{
		Type:         SocketFilter,
		License:      "MIT",
		Instructions: invalid,
	}

	_, err := newProgram(t, spec, nil)
	check(t, err)

	// Run tests against a valid program from here on out.
	spec.Instructions = valid

	// Explicitly request verifier log for a valid program and a start size.
	prog := mustNewProgram(t, spec, &ProgramOptions{
		LogLevel:     LogLevelInstruction,
		LogSizeStart: minVerifierLogSize * 2,
	})
	qt.Assert(t, qt.IsTrue(len(prog.VerifierLog) > minVerifierLogSize))
}

func TestProgramTestRunSyscall(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.14", "BPF_PROG_TYPE_SYSCALL")

	prog := mustNewProgram(t, &ProgramSpec{
		Type:    Syscall,
		Flags:   sys.BPF_F_SLEEPABLE,
		License: "MIT",
		Instructions: []asm.Instruction{
			// fn (ctx *u64) { *ctx++; return *ctx }
			asm.LoadMem(asm.R0, asm.R1, 0, asm.DWord),
			asm.Add.Imm(asm.R0, 1),
			asm.StoreMem(asm.R1, 0, asm.R0, asm.DWord),
			asm.Return(),
		},
	}, nil)

	// only Context
	rc, err := prog.Run(&RunOptions{Context: uint64(42)})
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, qt.Equals(rc, 43))

	// Context and ContextOut
	out := uint64(0)
	rc, err = prog.Run(&RunOptions{Context: uint64(99), ContextOut: &out})
	if err != nil {
		t.Fatal(err)
	}
	qt.Assert(t, qt.Equals(rc, 100))
	qt.Assert(t, qt.Equals(out, 100))
}
