package testutils

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
)

const marker = byte(0x16) // ^V

var (
	t2jSkip = string(marker) + "--- SKIP:"
	t2jFail = string(marker) + "--- FAIL:"
)

// t2jParser implements an io.Writer that parses test2json output. It looks for
// lines starting with the test2json markers for skip and fail, and applies
// those verdicts to the parent test when Apply is called. Lines without markers
// are passed through directly to the underlying writer (typically os.Stdout).
//
// Running a test with -test.v=test2json does not make it produce JSON output.
// Rather, it causes output lines of the test harness to be prefixed with a
// marker byte, making it easy to differentiate test output and harness output.
// See cmd/internal/test2json/test2json.go in the Go source tree for more
// details on the test2json format.
type t2jParser struct {
	tb  testing.TB
	out io.Writer

	mu   sync.Mutex
	line bytes.Buffer

	skipped bool
	failed  bool
}

func newt2jParser(tb testing.TB, out io.Writer) *t2jParser {
	return &t2jParser{
		tb:  tb,
		out: out,
	}
}

func (w *t2jParser) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *t2jParser) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	var written int
	for len(p) > 0 {
		var n int
		var err error

		if p[0] == marker || w.line.Len() > 0 {
			// Line starts with marker, or this is a line continuation.
			n, err = w.buffer(p)
		} else {
			// Test output without marker, pass through directly.
			n, err = w.passthrough(p)
		}

		written += n
		p = p[n:]

		if err != nil {
			return written, err
		}
	}

	return written, nil
}

// buffer accumulates data until it sees a newline, then parses the line for
// test2json markers.
func (w *t2jParser) buffer(p []byte) (int, error) {
	i := bytes.IndexByte(p, '\n')
	if i == -1 {
		// No newline in incoming data, keep it in buffer.
		_, _ = w.line.Write(p)
		return len(p), nil
	}

	// Write up to and including the newline, then parse the line.
	_, _ = w.line.Write(p[:i+1])
	return i + 1, w.parseLine()
}

func (w *t2jParser) parseLine() error {
	line := w.line.String()

	switch {
	case strings.HasPrefix(line, t2jSkip):
		w.skipped = true
	case strings.HasPrefix(line, t2jFail):
		w.failed = true
	}

	w.line.Reset()

	return nil
}

// passthrough writes p to the output until it sees a newline.
func (w *t2jParser) passthrough(p []byte) (int, error) {
	i := bytes.IndexByte(p, '\n')
	if i == -1 {
		return w.out.Write(p)
	}

	return w.out.Write(p[:i+1])
}

// Apply applies a skip/fail verdict to the parent test.
func (w *t2jParser) Apply() {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.skipped {
		w.tb.SkipNow()
	}

	if w.failed {
		w.tb.FailNow()
	}
}
