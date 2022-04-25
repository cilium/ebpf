package btf

import "testing"

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
