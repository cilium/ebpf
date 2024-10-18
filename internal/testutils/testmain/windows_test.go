package testmain

import (
	"bytes"
	"compress/gzip"
	"os"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestSummariseWPRTrace(t *testing.T) {
	f, err := os.Open("testdata/trace.xml.gz")
	qt.Assert(t, qt.IsNil(err))
	defer f.Close()

	trace, err := gzip.NewReader(f)
	qt.Assert(t, qt.IsNil(err))

	var buf bytes.Buffer
	qt.Assert(t, qt.IsNil(summariseWPRTrace(trace, &buf)))
	t.Log("\n", buf.String())
}
