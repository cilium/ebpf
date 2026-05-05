package ringbuf

import (
	"errors"
	"fmt"
	"os"
	"time"
)

func readWithPoll(poller poller, ring eventRing, deadline time.Time, haveData *bool, pendingErr *error, read func() error) error {
	if ring == nil {
		return fmt.Errorf("ringbuffer: %w", ErrClosed)
	}

	for {
		if !*haveData {
			if pe := *pendingErr; pe != nil {
				*pendingErr = nil
				return pe
			}

			err := poller.Wait(deadline)
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, ErrFlushed) {
				// Ignoring this for reading a valid entry after timeout or flush.
				// This can occur if the producer submitted to the ring buffer
				// with BPF_RB_NO_WAKEUP.
				*pendingErr = err
			} else if err != nil {
				return err
			}
			*haveData = true
		}

		for {
			err := read()
			// Not using errors.Is which is quite a bit slower.
			// For a tight loop it might make a difference.
			if err == errBusy {
				continue
			}
			if err == errEOR {
				*haveData = false
				break
			}
			return err
		}
	}
}
