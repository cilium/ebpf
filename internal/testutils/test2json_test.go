package testutils

import (
	"bytes"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestT2JParser(t *testing.T) {
	t.Run("plain output", func(t *testing.T) {
		var out bytes.Buffer
		p := newt2jParser(t, &out)
		input := "plain\noutput"
		n, err := p.WriteString(input)
		qt.Assert(t, qt.IsNil(err))

		qt.Assert(t, qt.Equals(n, len(input)))
		qt.Assert(t, qt.Equals(out.String(), input))
		qt.Assert(t, qt.Equals(p.failed, false))
		qt.Assert(t, qt.Equals(p.skipped, false))
	})

	t.Run("fail marker", func(t *testing.T) {
		var out bytes.Buffer
		p := newt2jParser(t, &out)
		input := t2jFail + " TestSomething (0.00s)\noutput\n"
		n, err := p.WriteString(input)
		qt.Assert(t, qt.IsNil(err))

		qt.Assert(t, qt.Equals(n, len(input)))
		qt.Assert(t, qt.Equals(p.failed, true))
		qt.Assert(t, qt.Equals(p.skipped, false))
		qt.Assert(t, qt.Equals(out.String(), "output\n"))
	})

	t.Run("skip marker", func(t *testing.T) {
		var out bytes.Buffer
		p := newt2jParser(t, &out)
		input := t2jSkip + " TestSomething (0.00s)\noutput\n"
		n, err := p.WriteString(input)
		qt.Assert(t, qt.IsNil(err))

		qt.Assert(t, qt.Equals(n, len(input)))
		qt.Assert(t, qt.Equals(p.failed, false))
		qt.Assert(t, qt.Equals(p.skipped, true))
		qt.Assert(t, qt.Equals(out.String(), "output\n"))
	})

	t.Run("marker without newline", func(t *testing.T) {
		var out bytes.Buffer
		p := newt2jParser(t, &out)
		input := t2jFail + " TestSomething (0.00s)"
		n, err := p.WriteString(input)
		qt.Assert(t, qt.IsNil(err))

		qt.Assert(t, qt.Equals(n, len(input)))
		qt.Assert(t, qt.Equals(p.failed, false))
		qt.Assert(t, qt.Equals(p.skipped, false))
		qt.Assert(t, qt.Equals(out.String(), ""))

		// The marker line should be buffered until we see a newline.
		_, err = p.WriteString("\n")
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(p.failed, true))
		qt.Assert(t, qt.Equals(out.String(), ""))
	})
}
