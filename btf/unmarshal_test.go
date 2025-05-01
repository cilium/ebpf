package btf

import (
	"iter"
	"math"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestFuzzyStringIndex(t *testing.T) {
	idx := newFuzzyStringIndex(10)
	count := testing.AllocsPerRun(1, func() {
		idx.Add([]byte("foo"), 1)
	})
	qt.Assert(t, qt.Equals(count, 0))

	idx.entries = idx.entries[:0]
	idx.Add([]byte("foo"), 1)
	idx.Add([]byte("bar"), 2)
	idx.Add([]byte("baz"), 3)
	idx.Build()

	all := func(it iter.Seq[TypeID]) (ids []TypeID) {
		for id := range it {
			ids = append(ids, id)
		}
		return
	}

	qt.Assert(t, qt.SliceContains(all(idx.Find("foo")), 1))
	qt.Assert(t, qt.SliceContains(all(idx.Find("bar")), 2))
	qt.Assert(t, qt.SliceContains(all(idx.Find("baz")), 3))

	qt.Assert(t, qt.IsTrue(newFuzzyStringIndexEntry(0, math.MaxUint32) < newFuzzyStringIndexEntry(1, 0)))
}
