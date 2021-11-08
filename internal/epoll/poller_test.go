package epoll

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf/internal/unix"
)

func TestPoller(t *testing.T) {
	event, err := newEventFd()
	if err != nil {
		t.Fatal(err)
	}
	defer event.close()

	poller, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer poller.Close()

	if err := poller.Add(event.raw, 42); err != nil {
		t.Fatal("Can't add fd:", err)
	}

	done := make(chan struct{}, 1)
	read := func() {
		defer func() {
			done <- struct{}{}
		}()

		events := make([]unix.EpollEvent, 1)

		n, err := poller.Wait(events)
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
