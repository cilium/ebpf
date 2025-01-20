package ebpf

import (
	"bytes"
	"math"
	"runtime"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/testutils"
	"github.com/cilium/ebpf/internal/unix"
)

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
			_, err := NewProgramWithOptions(progSpec, ProgramOptions{
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
