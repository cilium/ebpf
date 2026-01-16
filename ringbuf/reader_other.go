//go:build !windows

package ringbuf

import (
	"context"
	"time"

	"github.com/cilium/ebpf/internal/epoll"
	"github.com/cilium/ebpf/internal/unix"
)

var ErrFlushed = epoll.ErrFlushed

type poller struct {
	*epoll.Poller
	events []unix.EpollEvent
}

func newPoller(fd int) (*poller, error) {
	ep, err := epoll.New()
	if err != nil {
		return nil, err
	}

	if err := ep.Add(fd, 0); err != nil {
		ep.Close()
		return nil, err
	}

	return &poller{
		Poller: ep,
		events: make([]unix.EpollEvent, 1),
	}, nil
}

// Returns [os.ErrDeadlineExceeded] if a deadline was set and no wakeup was received.
// Returns [ErrFlushed] if the ring buffer was flushed manually.
func (p *poller) Wait(ctx context.Context, deadline time.Time) error {
	return waitWithContext(ctx, func() error {
		_, err := p.Poller.Wait(p.events, deadline)
		return err
	}, p.Poller)
}
