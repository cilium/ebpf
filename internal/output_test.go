package internal

import (
	"testing"

	"github.com/go-quicktest/qt"
)

type foo struct{}

func TestGoTypeName(t *testing.T) {
	type bar[T any] struct{}
	qt.Assert(t, qt.Equals(GoTypeName(foo{}), "foo"))
	qt.Assert(t, qt.Equals(GoTypeName(new(foo)), "foo"))
	qt.Assert(t, qt.Equals(GoTypeName(new(*foo)), "foo"))
	qt.Assert(t, qt.Equals(GoTypeName(bar[int]{}), "bar[int]"))
	qt.Assert(t, qt.Equals(GoTypeName(bar[foo]{}), "bar[foo]"))
	qt.Assert(t, qt.Equals(GoTypeName(bar[testing.T]{}), "bar[testing.T]"))
}
