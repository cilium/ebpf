package btf

import "testing"

func TestTypeMap(t *testing.T) {
	m := make(typeMap[int])

	a := new(Int)
	b := new(Int)

	m.Set(a, 42)
	if v, ok := m.Get(a); !ok {
		t.Error("Expected a to be present")
	} else if v != 42 {
		t.Error("Expected a to be 42, got", v)
	}

	if _, ok := m.Get(b); ok {
		t.Error("Expected b to be absent")
	}

	m.Set(b, 23)
	if v, ok := m.Get(b); !ok {
		t.Error("Expected b to be present")
	} else if v != 23 {
		t.Error("Expected b to be 23, got", v)
	}

	if v, _ := m.Get(a); v != 42 {
		t.Error("Expected a to be 42 after setting b, got", v)
	}
}

func BenchmarkTypeMapGet(b *testing.B) {
	types := make([]Type, 100000)
	for i := range types {
		types[i] = new(Int)
	}

	typ := types[0]

	b.Run("typeMap", func(b *testing.B) {
		m := make(typeMap[struct{}])
		for _, t := range types {
			m.Set(t, struct{}{})
		}

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			m.Get(typ)
		}
	})

	b.Run("map[Type]", func(b *testing.B) {
		m := make(map[Type]struct{})
		for _, t := range types {
			m[t] = struct{}{}
		}

		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			_, _ = m[typ]
		}
	})
}
