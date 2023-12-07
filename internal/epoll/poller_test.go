package epoll

import (
	"errors"
	"math"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/internal/unix"
)

func TestPoller(t *testing.T) {
	t.Parallel()

	event, poller := mustNewPoller(t)

	done := make(chan struct{}, 1)
	read := func() {
		defer func() {
			done <- struct{}{}
		}()

		events := make([]unix.EpollEvent, 1)

		n, err := poller.Wait(events, time.Time{})
		if errors.Is(err, os.ErrClosed) {
			return
		}

		if err != nil {
			t.Error("Error from wait:", err)
			return
		}

		if n != 1 {
			t.Errorf("Got %d instead of 1 events", n)
		}

		if e := events[0]; e.Pad != 42 {
			t.Errorf("Incorrect value in EpollEvent.Pad: %d != 42", e.Pad)
		}
	}

	if err := event.add(1); err != nil {
		t.Fatal(err)
	}

	go read()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Timed out")
	}

	if _, err := event.read(); err != nil {
		t.Fatal(err)
	}

	go read()
	select {
	case <-done:
		t.Fatal("Wait doesn't block")
	case <-time.After(time.Second):
	}

	if err := poller.Close(); err != nil {
		t.Fatal("Close returns an error:", err)
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close doesn't unblock Wait")
	}

	if err := poller.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatal("Closing a second time doesn't return ErrClosed:", err)
	}
}

func TestPollerDeadline(t *testing.T) {
	t.Parallel()

	_, poller := mustNewPoller(t)
	events := make([]unix.EpollEvent, 1)

	_, err := poller.Wait(events, time.Now().Add(-time.Second))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("Expected os.ErrDeadlineExceeded on deadline in the past, got", err)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)

		_, err := poller.Wait(events, time.Now().Add(math.MaxInt64))
		if !errors.Is(err, os.ErrClosed) {
			t.Error("Expected os.ErrClosed when interrupting deadline, got", err)
		}
	}()

	// Wait for the goroutine to enter the syscall.
	time.Sleep(time.Second)

	poller.Close()
	<-done
}

func mustNewPoller(t *testing.T) (*eventFd, *Poller) {
	t.Helper()

	event, err := newEventFd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { event.close() })

	poller, err := New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { poller.Close() })

	if err := poller.Add(event.raw, 42); err != nil {
		t.Fatal("Can't add fd:", err)
	}

	return event, poller
}
