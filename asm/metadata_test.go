package asm

import (
	"testing"
	"unsafe"

	qt "github.com/frankban/quicktest"
)

func TestMetadata(t *testing.T) {
	var m Metadata

	// Metadata should be the size of a pointer.
	qt.Assert(t, unsafe.Sizeof(m), qt.Equals, unsafe.Sizeof(uintptr(0)))

	// A lookup in a nil meta should return nil.
	qt.Assert(t, m.Get(bool(false)), qt.IsNil)

	// We can look up anything we inserted.
	m.Set(bool(false), int(0))
	m.Set(int(1), int(1))
	qt.Assert(t, m.Get(bool(false)), qt.Equals, int(0))
	qt.Assert(t, m.Get(int(1)), qt.Equals, int(1))

	// We have copy on write semantics
	old := m
	m.Set(bool(false), int(1))
	qt.Assert(t, m.Get(bool(false)), qt.Equals, int(1))
	qt.Assert(t, m.Get(int(1)), qt.Equals, int(1))
	qt.Assert(t, old.Get(bool(false)), qt.Equals, int(0))
	qt.Assert(t, old.Get(int(1)), qt.Equals, int(1))

	// Newtypes are handled distinctly.
	type b bool
	m.Set(b(false), int(42))
	qt.Assert(t, m.Get(bool(false)), qt.Equals, int(1))
	qt.Assert(t, m.Get(int(1)), qt.Equals, int(1))
	qt.Assert(t, m.Get(b(false)), qt.Equals, int(42))

	// Setting nil removes a key.
	m.Set(bool(false), nil)
	qt.Assert(t, m.Get(bool(false)), qt.IsNil)
	qt.Assert(t, m.Get(int(1)), qt.Equals, int(1))
	qt.Assert(t, m.Get(b(false)), qt.Equals, int(42))
}

func BenchmarkMetadata(b *testing.B) {
	// Assume that three bits of metadata on a single instruction is
	// our worst case.
	const worstCaseItems = 3

	type t struct{}

	b.Run("add first", func(b *testing.B) {
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			var v Metadata
			v.Set(t{}, 0)
		}
	})

	b.Run("add last", func(b *testing.B) {
		var m Metadata
		for i := 0; i < worstCaseItems-1; i++ {
			m.Set(i, i)
		}

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			v := m
			v.Set(t{}, 0)
		}
	})

	b.Run("add existing", func(b *testing.B) {
		var m Metadata
		for i := 0; i < worstCaseItems-1; i++ {
			m.Set(i, i)
		}
		m.Set(t{}, 0)

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			v := m
			v.Set(t{}, 0)
		}
	})

	b.Run("get miss", func(b *testing.B) {
		var m Metadata
		for i := 0; i < worstCaseItems; i++ {
			m.Set(i, i)
		}

		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			if m.Get(t{}) != nil {
				b.Fatal("got result from miss")
			}
		}
	})
}
