//go:build linux

// The netns implementation in this file was taken from cilium/cilium.
package testutils

import (
	"fmt"
	"os"
	"runtime"
	"testing"

	"golang.org/x/sync/errgroup"

	"github.com/cilium/ebpf/internal/unix"
)

type NetNS struct {
	f *os.File
}

// NewNetNS returns a new network namespace.
func NewNetNS(tb testing.TB) *NetNS {
	tb.Helper()

	ns, err := newNetNS()
	if err != nil {
		tb.Fatal(err)
	}

	tb.Cleanup(func() {
		ns.close()
	})

	return ns
}

// Do runs the provided func in the netns without changing the calling thread's
// netns.
//
// The code in f and any code called by f must NOT call [runtime.LockOSThread],
// as this could leave the goroutine created by Do permanently pinned to an OS
// thread.
func (h *NetNS) Do(f func() error) error {

	// Start the func in a new goroutine and lock it to an exclusive thread. This
	// ensures that if execution of the goroutine fails unexpectedly before we
	// call UnlockOSThread, the go runtime will ensure the underlying OS thread is
	// disposed of, rather than reused in a potentially undefined state.
	//
	// See also: https://pkg.go.dev/runtime#UnlockOSThread
	var g errgroup.Group
	g.Go(func() error {
		// Lock the newly-created goroutine to the OS thread it's running on so we
		// can safely move it into another network namespace. (per-thread state)
		restoreUnlock, err := lockOSThread()
		if err != nil {
			return err
		}

		if err := set(h.f); err != nil {
			return fmt.Errorf("set netns: %w (terminating OS thread)", err)
		}

		ferr := f()

		// Attempt to restore the underlying OS thread to its original network
		// namespace and unlock the running goroutine from its OS thread. Any
		// failures during this process will leave the goroutine locked, making the
		// underlying OS thread terminate when this function returns.
		if err := restoreUnlock(); err != nil {
			return fmt.Errorf("restore original netns: %w (terminating OS thread)", err)
		}
		return ferr
	})

	return g.Wait()
}

func newNetNS() (*NetNS, error) {
	var f *os.File

	// Perform network namespace creation in a new goroutine to give us the
	// possibility of terminating the underlying OS thread (by terminating the
	// goroutine) if something goes wrong.
	var g errgroup.Group
	g.Go(func() error {
		restoreUnlock, err := lockOSThread()
		if err != nil {
			return fmt.Errorf("lock OS thread: %w", err)
		}

		// Move the underlying OS thread to a new network namespace. This can be
		// undone by calling restoreUnlock().
		if err := unshare(); err != nil {
			return fmt.Errorf("create new netns: %w", err)
		}

		// Take out a reference to the new netns.
		f, err = getCurrent()
		if err != nil {
			return fmt.Errorf("get current netns: %w (terminating OS thread)", err)
		}

		// Restore the OS thread to its original network namespace or implicitly
		// terminate it if something went wrong.
		if err := restoreUnlock(); err != nil {
			return fmt.Errorf("restore current netns: %w (terminating OS thread)", err)
		}

		return nil
	})

	if err := g.Wait(); err != nil {
		return nil, err
	}

	ns := &NetNS{f: f}

	// Prevent resource leaks by eventually closing the underlying file descriptor
	// after ns is garbage collected.
	runtime.SetFinalizer(ns, (*NetNS).close)

	return ns, nil
}

func (h *NetNS) close() error {
	if h.f == nil {
		return nil
	}

	// Close closes the handle to the network namespace. This does not necessarily
	// mean destroying the network namespace itself, which only happens when all
	// references to it are gone and all of its processes have been terminated.
	if err := h.f.Close(); err != nil {
		return err
	}
	h.f = nil

	return nil
}

func lockOSThread() (func() error, error) {
	runtime.LockOSThread()

	orig, err := getCurrent()
	if err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("get current namespace: %w", err)
	}

	return func() error {
		defer orig.Close()

		if err := set(orig); err != nil {
			// We didn't manage to restore the OS thread to its original namespace.
			// Don't unlock the current goroutine from its thread, so the thread will
			// terminate when the current goroutine does.
			return err
		}

		// Original netns was restored, release the OS thread back into the
		// schedulable pool.
		runtime.UnlockOSThread()

		return nil
	}, nil
}

// unshare moves the calling OS thread of the calling goroutine to a new network
// namespace. Must only be called after a prior call to lockOSThread().
func unshare() error {
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return err
	}
	return nil
}

// set sets the underlying OS thread of the calling goroutine to the netns
// pointed at by f.
func set(f *os.File) error {
	return unix.Setns(int(f.Fd()), unix.CLONE_NEWNET)
}

// getCurrent gets a file descriptor to the current thread network namespace.
func getCurrent() (*os.File, error) {
	return getFromThread(os.Getpid(), unix.Gettid())
}

// getFromPath gets a file descriptor to the network namespace pinned at path.
func getFromPath(path string) (*os.File, error) {
	return os.OpenFile(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
}

// getFromThread gets a file descriptor to the network namespace of a given pid
// and tid.
func getFromThread(pid, tid int) (*os.File, error) {
	return getFromPath(fmt.Sprintf("/proc/%d/task/%d/ns/net", pid, tid))
}
