package ebpf

import (
	"math"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
)

const basicProgramType = SocketFilter
const xdpProgramType = XDP

func TestProgramTestRunInterrupt(t *testing.T) {
	testutils.SkipOnOldKernel(t, "5.0", "EINTR from BPF_PROG_TEST_RUN")

	prog := mustBasicProgram(t)

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

func TestProgramFromFD(t *testing.T) {
	prog := mustBasicProgram(t)

	// If you're thinking about copying this, don't. Use
	// Clone() instead.
	prog2, err := NewProgramFromFD(dupFD(t, prog.FD()))
	testutils.SkipIfNotSupported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	defer prog2.Close()

	// Name and type are supposed to be copied from program info.
	if haveObjName() == nil && prog2.name != "test" {
		t.Errorf("Expected program to have name test, got '%s'", prog2.name)
	}

	if prog2.typ != basicProgramType {
		t.Errorf("Expected program to have type %s, got '%s'", basicProgramType, prog2.typ)
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
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(prog.Close()))
}

func dupFD(tb testing.TB, fd int) int {
	tb.Helper()

	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 1)
	if err != nil {
		tb.Fatal("Can't dup fd:", err)
	}

	return dup
}
