package internal

import "math/bits"

// Dequeue implements a double ended queue.
type Dequeue[T any] struct {
	elems       []T
	read, write uint64
	mask        uint64
}

// Reset clears the contents of the dequeue while retaining the backing buffer.
func (dq *Dequeue[T]) Reset() {
	var zero T

	for i := dq.read; i < dq.write; i++ {
		dq.elems[i&dq.mask] = zero
	}

	dq.read, dq.write = 0, 0
}

func (dq *Dequeue[T]) Empty() bool {
	return dq.read == dq.write
}

// Push adds an element to the end.
func (dq *Dequeue[T]) Push(e T) {
	dq.Grow(1)
	dq.elems[dq.write&dq.mask] = e
	dq.write++
}

// Shift returns the first element or the zero value.
func (dq *Dequeue[T]) Shift() T {
	var zero T

	if dq.Empty() {
		return zero
	}

	index := dq.read & dq.mask
	t := dq.elems[index]
	dq.elems[index] = zero
	dq.read++
	return t
}

// Pop returns the last element or the zero value.
func (dq *Dequeue[T]) Pop() T {
	var zero T

	if dq.Empty() {
		return zero
	}

	dq.write--
	index := dq.write & dq.mask
	t := dq.elems[index]
	dq.elems[index] = zero
	return t
}

// Grow the dequeue's capacity, if necessary, to guarantee space for another n
// elements.
func (dq *Dequeue[T]) Grow(n int) {
	have := dq.write - dq.read
	need := have + uint64(n)
	if need < have {
		panic("overflow")
	}
	if uint64(len(dq.elems)) >= need {
		return
	}

	// Round up to the new power of two which is at least 8.
	// See https://jameshfisher.com/2018/03/30/round-up-power-2/
	capacity := 1 << (64 - bits.LeadingZeros64(need-1))
	if capacity < 8 {
		capacity = 8
	}

	elems := make([]T, have, capacity)
	pivot := dq.read & dq.mask
	copied := copy(elems, dq.elems[pivot:])
	copy(elems[copied:], dq.elems[:pivot])

	dq.elems = elems[:capacity]
	dq.mask = uint64(capacity) - 1
	dq.read, dq.write = 0, have
}
