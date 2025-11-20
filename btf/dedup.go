package btf

import (
	"fmt"
	"hash/maphash"
	"slices"
)

type deduper struct {
	visited    map[Type]struct{}
	hashCache  map[hashCacheKey]uint64
	known      map[Type]Type
	candidates map[uint64][]Type
	eqCache    map[typKey]bool
	seed       maphash.Seed
}

func newDeduper() *deduper {
	return &deduper{
		make(map[Type]struct{}),
		make(map[hashCacheKey]uint64),
		make(map[Type]Type),
		make(map[uint64][]Type),
		make(map[typKey]bool),
		maphash.MakeSeed(),
	}
}

func (dm *deduper) Deduplicate(t Type) Type {
	// If we have already attempted to deduplicate this exact type, return the result.
	if deduped, ok := dm.known[t]; ok {
		return deduped
	}

	// Visit the subtree, if a type has children, attempt to replace it with
	// a deduplicated version of those children.
	for t := range postorder(t, dm.visited) {
		for c := range children(t) {
			*c = dm.deduplicateSingle(*c)
		}
	}

	// Finally, deduplicate the root type itself.
	return dm.deduplicateSingle(t)
}

func (dm *deduper) deduplicateSingle(t Type) Type {
	// If we have deduplicated this type before, return the result of that deduplication.
	if deduped, ok := dm.known[t]; ok {
		return deduped
	}

	// Compute the hash of this type. Types with the same hash are candidates for deduplication.
	hash := dm.typeHash(t, -1, dm.hashCache)

	// A hash collision is possible, so we need to compare against all candidates with the same hash.
	candidates := dm.candidates[hash]
	for _, candidate := range candidates {
		// Pre-size the visited slice, experimentation on VMLinux shows a capacity of 16 to give the best performance.
		const visitedCapacity = 16
		if typesEquivalent(candidate, t, make([]Type, 0, visitedCapacity), dm.eqCache) {
			dm.known[t] = candidate
			return candidate
		}
	}

	dm.candidates[hash] = append(dm.candidates[hash], t)
	return t
}

// The hash of a type is the same given the type and depth budget, and thus is the key for the cache.
type hashCacheKey struct {
	t           Type
	depthBudget int
}

// typeHash computes a hash for `t`. The produced hash is the same for types which are similar.
// The hash can collide such that two different types may produce the same hash, so equivalence must be checked
// separately. It will recursively call itself to hash child types. The initial call should use a depthBudget of -1.
func (dm *deduper) typeHash(t Type, depthBudget int, cache map[hashCacheKey]uint64) uint64 {
	if depthBudget == 0 {
		return 0
	}

	var hash maphash.Hash
	h := &hash
	h.SetSeed(dm.seed)

	switch t := t.(type) {
	case *Void:
		maphash.WriteComparable(h, kindUnknown)
	case *Int:
		maphash.WriteComparable(h, kindInt)
		maphash.WriteComparable(h, *t)
	case *Pointer:
		maphash.WriteComparable(h, kindPointer)
		// If the depth budget is positive, decrement it every time we follow a pointer.
		if depthBudget > 0 {
			depthBudget--
		}

		// If this is the first time we are following a pointer, set the depth budget.
		// This limits amount of recursion we do when hashing pointers that form cycles.
		// This is cheaper than tracking visited types and works because hash collisions are
		// allowed.
		if depthBudget < 0 {
			depthBudget = 1

			// Double pointers are common in C. However, with a depth budget of 1,
			// all double pointers would hash the same, causing a performance issue
			// when checking equivalence. So we give double pointers a bit more budget.
			if _, ok := t.Target.(*Pointer); ok {
				depthBudget = 2
			}
		}
		maphash.WriteComparable(h, dm.typeHash(t.Target, depthBudget, cache))
	case *Array:
		maphash.WriteComparable(h, kindArray)
		maphash.WriteComparable(h, t.Nelems)
		maphash.WriteComparable(h, dm.typeHash(t.Index, depthBudget, cache))
		maphash.WriteComparable(h, dm.typeHash(t.Type, depthBudget, cache))
	case *Struct, *Union:
		// Check the cache to avoid recomputing the hash for this type and depth budget.
		key := hashCacheKey{t, depthBudget}
		if cached, ok := cache[key]; ok {
			return cached
		}

		var members []Member
		switch t := t.(type) {
		case *Struct:
			maphash.WriteComparable(h, kindStruct)
			maphash.WriteComparable(h, t.Name)
			maphash.WriteComparable(h, t.Size)
			members = t.Members
		case *Union:
			maphash.WriteComparable(h, kindUnion)
			maphash.WriteComparable(h, t.Name)
			maphash.WriteComparable(h, t.Size)
			members = t.Members
		}

		maphash.WriteComparable(h, len(members))
		for _, m := range members {
			maphash.WriteComparable(h, m.Name)
			maphash.WriteComparable(h, m.Offset)
			maphash.WriteComparable(h, dm.typeHash(m.Type, depthBudget, cache))
		}

		sum := h.Sum64()
		cache[key] = sum
		return sum
	case *Enum:
		maphash.WriteComparable(h, kindEnum)
		maphash.WriteComparable(h, t.Name)
		maphash.WriteComparable(h, t.Size)
		maphash.WriteComparable(h, t.Signed)
		for _, v := range t.Values {
			maphash.WriteComparable(h, v)
		}
	case *Fwd:
		maphash.WriteComparable(h, kindForward)
		maphash.WriteComparable(h, *t)
	case *Typedef:
		maphash.WriteComparable(h, kindTypedef)
		maphash.WriteComparable(h, t.Name)
		maphash.WriteComparable(h, dm.typeHash(t.Type, depthBudget, cache))
	case *Volatile:
		maphash.WriteComparable(h, kindVolatile)
		maphash.WriteComparable(h, dm.typeHash(t.Type, depthBudget, cache))
	case *Const:
		maphash.WriteComparable(h, kindConst)
		maphash.WriteComparable(h, dm.typeHash(t.Type, depthBudget, cache))
	case *Restrict:
		maphash.WriteComparable(h, kindRestrict)
		maphash.WriteComparable(h, dm.typeHash(t.Type, depthBudget, cache))
	case *Func:
		maphash.WriteComparable(h, kindFunc)
		maphash.WriteComparable(h, t.Name)
		maphash.WriteComparable(h, dm.typeHash(t.Type, depthBudget, cache))
	case *FuncProto:
		// It turns out that pointers to function prototypes are common in C code, function pointers.
		// Function prototypes frequently have similar patterns of [ptr, ptr] -> int, or [ptr, ptr, ptr] -> int.
		// Causing frequent hash collisions, for the default depth budget of 1.
		// So allow one additional level of pointers when we encounter a function prototype.
		if depthBudget >= 0 {
			depthBudget++
		}

		maphash.WriteComparable(h, kindFuncProto)
		for _, p := range t.Params {
			maphash.WriteComparable(h, p.Name)
			maphash.WriteComparable(h, dm.typeHash(p.Type, depthBudget, cache))
		}
		maphash.WriteComparable(h, dm.typeHash(t.Return, depthBudget, cache))
	case *Var:
		maphash.WriteComparable(h, kindVar)
		maphash.WriteComparable(h, t.Name)
		maphash.WriteComparable(h, t.Linkage)
		maphash.WriteComparable(h, dm.typeHash(t.Type, depthBudget, cache))
	case *Datasec:
		maphash.WriteComparable(h, kindDatasec)
		maphash.WriteComparable(h, t.Name)
		for _, v := range t.Vars {
			maphash.WriteComparable(h, v.Offset)
			maphash.WriteComparable(h, v.Size)
			maphash.WriteComparable(h, dm.typeHash(v.Type, depthBudget, cache))
		}
	case *declTag:
		maphash.WriteComparable(h, kindDeclTag)
		maphash.WriteComparable(h, t.Value)
		maphash.WriteComparable(h, t.Index)
		maphash.WriteComparable(h, dm.typeHash(t.Type, depthBudget, cache))
	case *TypeTag:
		maphash.WriteComparable(h, kindTypeTag)
		maphash.WriteComparable(h, t.Value)
		maphash.WriteComparable(h, dm.typeHash(t.Type, depthBudget, cache))
	case *Float:
		maphash.WriteComparable(h, kindFloat)
		maphash.WriteComparable(h, *t)
	default:
		panic(fmt.Sprintf("unsupported type for hashing: %T", t))
	}

	return h.Sum64()
}

type typKey struct {
	a Type
	b Type
}

// typesEquivalent checks if two types are functionally equivalent.
func typesEquivalent(aTyp, b Type, visited []Type, cache map[typKey]bool) bool {
	// Fast path: do a pointer comparison, if they are identical then they are also equivalent.
	if aTyp == b {
		return true
	}

	switch a := aTyp.(type) {
	case *Void:
		_, ok := b.(*Void)
		return ok
	case *Int:
		b, ok := b.(*Int)
		if !ok {
			return false
		}
		return a.Name == b.Name && a.Size == b.Size && a.Encoding == b.Encoding
	case *Enum:
		b, ok := b.(*Enum)
		if !ok {
			return false
		}
		if a.Name != b.Name || len(a.Values) != len(b.Values) {
			return false
		}
		for i := range a.Values {
			if a.Values[i].Name != b.Values[i].Name || a.Values[i].Value != b.Values[i].Value {
				return false
			}
		}
		return true
	case *Fwd:
		b, ok := b.(*Fwd)
		if !ok {
			return false
		}
		return a.Name == b.Name && a.Kind == b.Kind
	case *Float:
		b, ok := b.(*Float)
		if !ok {
			return false
		}
		return a.Name == b.Name && a.Size == b.Size
	case *Array:
		b, ok := b.(*Array)
		if !ok {
			return false
		}

		return a.Nelems == b.Nelems &&
			typesEquivalent(a.Index, b.Index, visited, cache) &&
			typesEquivalent(a.Type, b.Type, visited, cache)
	case *Pointer:
		b, ok := b.(*Pointer)
		if !ok {
			return false
		}

		// Detect cycles by tracking visited types. Assume types are equivalent if we have already
		// visited this type in the current equivalence check.
		if slices.Contains(visited, aTyp) {
			return true
		}
		visited = append(visited, aTyp)

		return typesEquivalent(a.Target, b.Target, visited, cache)
	case *Struct, *Union:
		// Use a cache to avoid recomputation. We only do this for composite types since they are
		// where types fan out the most. For other types, the overhead of the lookup and update
		// outweighs performance benefits.
		cacheKey := typKey{a: aTyp, b: b}
		if equal, ok := cache[cacheKey]; ok {
			return equal
		}

		equal := compositeEquivalent(aTyp, b, visited, cache)
		cache[cacheKey] = equal
		return equal
	case *Typedef:
		b, ok := b.(*Typedef)
		if !ok {
			return false
		}
		return a.Name == b.Name && typesEquivalent(a.Type, b.Type, visited, cache)
	case *Volatile:
		b, ok := b.(*Volatile)
		if !ok {
			return false
		}
		return typesEquivalent(a.Type, b.Type, visited, cache)
	case *Const:
		b, ok := b.(*Const)
		if !ok {
			return false
		}
		return typesEquivalent(a.Type, b.Type, visited, cache)
	case *Restrict:
		b, ok := b.(*Restrict)
		if !ok {
			return false
		}
		return typesEquivalent(a.Type, b.Type, visited, cache)
	case *Func:
		b, ok := b.(*Func)
		if !ok {
			return false
		}
		return a.Name == b.Name && typesEquivalent(a.Type, b.Type, visited, cache)
	case *FuncProto:
		b, ok := b.(*FuncProto)
		if !ok {
			return false
		}

		if !typesEquivalent(a.Return, b.Return, visited, cache) || len(a.Params) != len(b.Params) {
			return false
		}
		for i := range a.Params {
			if a.Params[i].Name != b.Params[i].Name ||
				!typesEquivalent(a.Params[i].Type, b.Params[i].Type, visited, cache) {
				return false
			}
		}
		return true
	case *Var:
		b, ok := b.(*Var)
		if !ok {
			return false
		}
		return a.Name == b.Name &&
			typesEquivalent(a.Type, b.Type, visited, cache) &&
			a.Linkage == b.Linkage
	case *Datasec:
		b, ok := b.(*Datasec)
		if !ok {
			return false
		}
		if a.Name != b.Name || len(a.Vars) != len(b.Vars) {
			return false
		}
		for i := range a.Vars {
			if a.Vars[i].Offset != b.Vars[i].Offset ||
				a.Vars[i].Size != b.Vars[i].Size ||
				!typesEquivalent(a.Vars[i].Type, b.Vars[i].Type, visited, cache) {
				return false
			}
		}
		return true
	case *declTag:
		b, ok := b.(*declTag)
		if !ok {
			return false
		}
		return a.Value == b.Value &&
			a.Index == b.Index &&
			typesEquivalent(a.Type, b.Type, visited, cache)
	case *TypeTag:
		b, ok := b.(*TypeTag)
		if !ok {
			return false
		}
		return a.Value == b.Value &&
			typesEquivalent(a.Type, b.Type, visited, cache)
	default:
		panic(fmt.Sprintf("unsupported type for equivalence: %T", a))
	}
}

func compositeEquivalent(aTyp, b Type, visited []Type, cache map[typKey]bool) bool {
	var membersA, membersB []Member
	switch a := aTyp.(type) {
	case *Struct:
		b, ok := b.(*Struct)
		if !ok {
			return false
		}

		if a.Name != b.Name || a.Size != b.Size || len(a.Members) != len(b.Members) {
			return false
		}
		membersA = a.Members
		membersB = b.Members
	case *Union:
		b, ok := b.(*Union)
		if !ok {
			return false
		}

		if a.Name != b.Name || a.Size != b.Size || len(a.Members) != len(b.Members) {
			return false
		}
		membersA = a.Members
		membersB = b.Members
	}

	for i := range membersA {
		if membersA[i].Name != membersB[i].Name || membersA[i].Offset != membersB[i].Offset {
			return false
		}

		if !typesEquivalent(membersA[i].Type, membersB[i].Type, visited, cache) {
			return false
		}
	}

	return true
}
