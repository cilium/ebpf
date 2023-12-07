package internal

import "testing"

func TestDeque(t *testing.T) {
	t.Run("pop", func(t *testing.T) {
		var dq Deque[int]
		dq.Push(1)
		dq.Push(2)

		if dq.Pop() != 2 {
			t.Error("Didn't pop 2 first")
		}

		if dq.Pop() != 1 {
			t.Error("Didn't pop 1 second")
		}

		if dq.Pop() != 0 {
			t.Error("Didn't pop zero")
		}
	})

	t.Run("shift", func(t *testing.T) {
		var td Deque[int]
		td.Push(1)
		td.Push(2)

		if td.Shift() != 1 {
			t.Error("Didn't shift 1 first")
		}

		if td.Shift() != 2 {
			t.Error("Didn't shift b second")
		}

		if td.Shift() != 0 {
			t.Error("Didn't shift zero")
		}
	})

	t.Run("push", func(t *testing.T) {
		var td Deque[int]
		td.Push(1)
		td.Push(2)
		td.Shift()

		for i := 1; i <= 12; i++ {
			td.Push(i)
		}

		if td.Shift() != 2 {
			t.Error("Didn't shift 2 first")
		}
		for i := 1; i <= 12; i++ {
			if v := td.Shift(); v != i {
				t.Fatalf("Shifted %d at pos %d", v, i)
			}
		}
	})

	t.Run("grow", func(t *testing.T) {
		var td Deque[int]
		td.Push(1)
		td.Push(2)
		td.Push(3)
		td.Shift()

		td.Grow(7)
		if len(td.elems) < 9 {
			t.Fatal("Expected at least 9 elements, got", len(td.elems))
		}

		if cap(td.elems)&(cap(td.elems)-1) != 0 {
			t.Fatalf("Capacity %d is not a power of two", cap(td.elems))
		}

		if td.Shift() != 2 || td.Shift() != 3 {
			t.Fatal("Elements don't match after grow")
		}
	})
}
