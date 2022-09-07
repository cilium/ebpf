package btf

// walkType calls fn on each child of typ.
//
// It's faster than directly invoking typ.children for some common types.
func walkType(typ Type, fn func(*Type)) {
	walk := func(children []*Type) {
		for _, c := range children {
			fn(c)
		}
	}

	// Explicitly type switch on the most common types to allow the inliner to
	// do its work. This avoids allocating intermediate slices from walk() on
	// the heap.
	switch v := typ.(type) {
	case *Void:
		walk(v.children())
	case *Int:
		walk(v.children())
	case *Pointer:
		walk(v.children())
	case *Array:
		walk(v.children())
	case *Struct:
		walk(v.children())
	case *Union:
		walk(v.children())
	case *Enum:
		walk(v.children())
	case *Fwd:
		walk(v.children())
	case *Typedef:
		walk(v.children())
	case *Volatile:
		walk(v.children())
	case *Const:
		walk(v.children())
	case *Restrict:
		walk(v.children())
	case *Func:
		walk(v.children())
	case *FuncProto:
		walk(v.children())
	case *Var:
		walk(v.children())
	case *Datasec:
		walk(v.children())
	default:
		walk(v.children())
	}
}
