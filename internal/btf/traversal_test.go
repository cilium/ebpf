package btf

import (
	"testing"

	qt "github.com/frankban/quicktest"
)

func TestFlatten(t *testing.T) {
	ptr := newCyclicalType(2).(*Pointer)
	cst := ptr.Target.(*Const)
	str := cst.Type.(*Struct)

	types := flattenType(ptr, nil)
	qt.Assert(t, types, qt.HasLen, 3)
	qt.Assert(t, types[0], qt.Equals, ptr)
	qt.Assert(t, types[1], qt.Equals, cst)
	qt.Assert(t, types[2], qt.Equals, str)

	types = flattenType(ptr, func(t Type) bool { return t == cst })
	qt.Assert(t, types, qt.HasLen, 1)
	qt.Assert(t, types[0], qt.Equals, ptr)
}

func TestTypeDeque(t *testing.T) {
	a, b := new(Type), new(Type)

	t.Run("pop", func(t *testing.T) {
		var td typeDeque
		td.push(a)
		td.push(b)

		if td.pop() != b {
			t.Error("Didn't pop b first")
		}

		if td.pop() != a {
			t.Error("Didn't pop a second")
		}

		if td.pop() != nil {
			t.Error("Didn't pop nil")
		}
	})

	t.Run("shift", func(t *testing.T) {
		var td typeDeque
		td.push(a)
		td.push(b)

		if td.shift() != a {
			t.Error("Didn't shift a second")
		}

		if td.shift() != b {
			t.Error("Didn't shift b first")
		}

		if td.shift() != nil {
			t.Error("Didn't shift nil")
		}
	})

	t.Run("push", func(t *testing.T) {
		var td typeDeque
		td.push(a)
		td.push(b)
		td.shift()

		ts := make([]Type, 12)
		for i := range ts {
			td.push(&ts[i])
		}

		if td.shift() != b {
			t.Error("Didn't shift b first")
		}
		for i := range ts {
			if td.shift() != &ts[i] {
				t.Fatal("Shifted wrong Type at pos", i)
			}
		}
	})

	t.Run("all", func(t *testing.T) {
		var td typeDeque
		td.push(a)
		td.push(b)

		all := td.all()
		if len(all) != 2 {
			t.Fatal("Expected 2 elements, got", len(all))
		}

		if all[0] != a || all[1] != b {
			t.Fatal("Elements don't match")
		}
	})
}
