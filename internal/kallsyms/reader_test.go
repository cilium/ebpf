package kallsyms

import (
	"bytes"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestReader(t *testing.T) {
	b := []byte(`
one  two 		three
  four  

  λέξη	`)

	r := newReader(bytes.NewReader(b))

	qt.Assert(t, qt.IsTrue(r.Line()))
	qt.Assert(t, qt.IsTrue(r.Word()))
	qt.Assert(t, qt.Equals(r.Text(), "one"))

	qt.Assert(t, qt.IsTrue(r.Word()))
	qt.Assert(t, qt.Equals(r.Text(), "two"))

	qt.Assert(t, qt.IsTrue(r.Word()))
	qt.Assert(t, qt.Equals(r.Text(), "three"))
	qt.Assert(t, qt.IsFalse(r.Word()))

	qt.Assert(t, qt.IsTrue(r.Line()))
	qt.Assert(t, qt.IsTrue(r.Word()))
	qt.Assert(t, qt.Equals(r.Text(), "four"))
	qt.Assert(t, qt.IsFalse(r.Word()))

	qt.Assert(t, qt.IsTrue(r.Line()))
	qt.Assert(t, qt.IsTrue(r.Word()))
	qt.Assert(t, qt.Equals(r.Text(), "λέξη"))
	qt.Assert(t, qt.IsFalse(r.Word()))

	qt.Assert(t, qt.IsFalse(r.Line()))
	qt.Assert(t, qt.IsNil(r.Err()))
}
