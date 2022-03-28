package asm

import (
	"testing"
	"unsafe"

	qt "github.com/frankban/quicktest"
)

func TestMetadata(t *testing.T) {
	var m Metadata

	t.Log("size:", unsafe.Sizeof(m))

	// A lookup in a nil meta should return nil.
	qt.Assert(t, m.Get(bool(false)), qt.IsNil)

	// We can look up anything we inserted.
	m.Set(bool(false), int(0))
	qt.Assert(t, m.Get(bool(false)), qt.Equals, int(0))

	// We have copy on write semantics
	old := m
	m.Set(bool(false), int(1))
	qt.Assert(t, m.Get(bool(false)), qt.Equals, int(1))
	qt.Assert(t, old.Get(bool(false)), qt.Equals, int(0))

	// Newtypes are handled distinctly.
	type b bool
	m.Set(b(false), int(42))
	qt.Assert(t, m.Get(bool(false)), qt.Equals, int(1))
	qt.Assert(t, m.Get(b(false)), qt.Equals, int(42))

	// Setting nil removes a key.
	m.Set(bool(false), nil)
	qt.Assert(t, m.Get(bool(false)), qt.IsNil)
}

func BenchmarkMetadata(b *testing.B) {
	type k struct{}

	b.Run("set", func(b *testing.B) {
		var m Metadata
		for i := 0; i < 4; i++ {
			m.Set(i, i)
		}
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			m.Set(k{}, b.N)
		}
	})

	b.Run("set existing", func(b *testing.B) {
		var m Metadata
		for i := 0; i < 3; i++ {
			m.Set(i, i)
		}
		m.Set(k{}, 0)
		b.ReportAllocs()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			m.Set(k{}, 0)
		}
	})
}
