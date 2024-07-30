package testmain

import (
	"bytes"
	"os"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestSummariseWPRTrace(t *testing.T) {
	f, err := os.Open("testdata/trace.xml")
	qt.Assert(t, qt.IsNil(err))
	defer f.Close()

	var buf bytes.Buffer
	qt.Assert(t, qt.IsNil(summariseWPRTrace(f, &buf)))
	t.Log("\n", buf.String())
}
