package btf

// Functions to traverse a cyclic graph of types. The below was very useful:
// https://eli.thegreenplace.net/2015/directed-graph-traversal-orderings-and-applications-to-data-flow-analysis/#post-order-and-reverse-post-order

// preorderTraversal returns all types reachable from typ, in preorder.
//
// This means that children of typ appear before typ in the resulting slice.
//
// Types for which skip returns true are ignored. skip may be nil.
func preorderTraversal(typ Type, skip func(Type) bool) []Type {
	var (
		// Contains types which need to be visited.
		todo typeDeque
		// Any type which has been pushed is present. Any type which has been
		// walked has a true value.
		walked = make(map[Type]bool)
		// Contains types which have been fully visited.
		result []Type
	)

	push := func(t *Type) {
		if _, ok := walked[*t]; ok {
			// This type has been pushed or walked before, skip it.
			return
		}

		if skip != nil && skip(*t) {
			return
		}

		// Prevent another push, but allow walking.
		walked[*t] = false
		todo.push(t)
	}

	walk := func(t Type) {
		// Prevent walking or pushing the type.
		walked[t] = true

		// Add children of t to todo.
		walkType(t, push)
	}

	// Unroll the iteration for typ. This let's us avoid taking &typ which would
	// force it to be heap allocated.
	if skip != nil && skip(typ) {
		return nil
	}

	walk(typ)

	for !todo.empty() {
		t := todo.pop()

		if !walked[*t] {
			// Push the type again. The next time we pop it, walked[*t] will be
			// true.
			todo.push(t)

			// Add all direct children to todo.
			walk(*t)
		} else {
			// We've walked *t already, so we know that all children have been
			// handled. Add *t to the result.
			result = append(result, *t)
		}
	}

	result = append(result, typ)
	return result
}

// typeDeque keeps track of pointers to types which still
// need to be visited.
type typeDeque struct {
	types       []*Type
	read, write uint64
	mask        uint64
}

func (dq *typeDeque) empty() bool {
	return dq.read == dq.write
}

// push adds a type to the stack.
func (dq *typeDeque) push(t *Type) {
	if dq.write-dq.read < uint64(len(dq.types)) {
		dq.types[dq.write&dq.mask] = t
		dq.write++
		return
	}

	new := len(dq.types) * 2
	if new == 0 {
		new = 8
	}

	types := make([]*Type, new)
	pivot := dq.read & dq.mask
	n := copy(types, dq.types[pivot:])
	n += copy(types[n:], dq.types[:pivot])
	types[n] = t

	dq.types = types
	dq.mask = uint64(new) - 1
	dq.read, dq.write = 0, uint64(n+1)
}

// shift returns the first element or null.
func (dq *typeDeque) shift() *Type {
	if dq.empty() {
		return nil
	}

	index := dq.read & dq.mask
	t := dq.types[index]
	dq.types[index] = nil
	dq.read++
	return t
}

// pop returns the last element or null.
func (dq *typeDeque) pop() *Type {
	if dq.empty() {
		return nil
	}

	dq.write--
	index := dq.write & dq.mask
	t := dq.types[index]
	dq.types[index] = nil
	return t
}

// all returns all elements.
//
// The deque is empty after calling this method.
func (dq *typeDeque) all() []*Type {
	length := dq.write - dq.read
	types := make([]*Type, 0, length)
	for t := dq.shift(); t != nil; t = dq.shift() {
		types = append(types, t)
	}
	return types
}
