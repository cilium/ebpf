package btf

import (
	"errors"
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

func (dm *deduper) deduplicate(t Type) (Type, error) {
	// If we have already attempted to deduplicate this exact type, return the result.
	if deduped, ok := dm.known[t]; ok {
		return deduped, nil
	}

	// Visit the subtree, if a type has children, attempt to replace it with
	// a deduplicated version of those children.
	for t := range postorder(t, dm.visited) {
		for c := range children(t) {
			var err error
			*c, err = dm.deduplicateSingle(*c)
			if err != nil {
				return nil, err
			}
		}
	}

	// Finally, deduplicate the root type itself.
	return dm.deduplicateSingle(t)
}

func (dm *deduper) deduplicateSingle(t Type) (Type, error) {
	// If we have deduplicated this type before, return the result of that deduplication.
	if deduped, ok := dm.known[t]; ok {
		return deduped, nil
	}

	// Compute the hash of this type. Types with the same hash are candidates for deduplication.
	hash, err := dm.typeHash(t, -1, dm.hashCache)
	if err != nil {
		return nil, err
	}

	// A hash collision is possible, so we need to compare against all candidates with the same hash.
	candidates := dm.candidates[hash]
	for _, candidate := range candidates {
		// Pre-size the visited slice, experimentation on VMLinux shows a capacity of 16 to give the best performance.
		const visitedCapacity = 16
		err := typesEquivalent(candidate, t, make([]Type, 0, visitedCapacity), dm.eqCache)
		if err != nil {
			if errors.Is(err, errNotEquivalent) {
				continue
			}
			return nil, err
		}

		dm.known[t] = candidate
		return candidate, nil
	}

	dm.candidates[hash] = append(dm.candidates[hash], t)
	return t, nil
}

// The hash of a type is the same given the type and depth budget, and thus is the key for the cache.
type hashCacheKey struct {
	t           Type
	depthBudget int
}

// typeHash computes a hash for `t`. The produced hash is the same for types which are similar.
// The hash can collide such that two different types may produce the same hash, so equivalence must be checked
// separately. It will recursively call itself to hash child types. The initial call should use a depthBudget of -1.
func (dm *deduper) typeHash(t Type, depthBudget int, cache map[hashCacheKey]uint64) (uint64, error) {
	if depthBudget == 0 {
		return 0, nil
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
		sub, err := dm.typeHash(t.Target, depthBudget, cache)
		if err != nil {
			return 0, err
		}
		maphash.WriteComparable(h, sub)
	case *Array:
		maphash.WriteComparable(h, kindArray)
		maphash.WriteComparable(h, t.Nelems)
		sub, err := dm.typeHash(t.Index, depthBudget, cache)
		if err != nil {
			return 0, err
		}
		maphash.WriteComparable(h, sub)
		_, err = dm.typeHash(t.Type, depthBudget, cache)
		if err != nil {
			return 0, err
		}
		maphash.WriteComparable(h, sub)
	case *Struct, *Union:
		// Check the cache to avoid recomputing the hash for this type and depth budget.
		key := hashCacheKey{t, depthBudget}
		if cached, ok := cache[key]; ok {
			return cached, nil
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
			sub, err := dm.typeHash(m.Type, depthBudget, cache)
			if err != nil {
				return 0, err
			}
			maphash.WriteComparable(h, sub)
		}

		sum := h.Sum64()
		cache[key] = sum
		return sum, nil
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
		sub, err := dm.typeHash(t.Type, depthBudget, cache)
		if err != nil {
			return 0, err
		}
		maphash.WriteComparable(h, sub)
	case *Volatile:
		maphash.WriteComparable(h, kindVolatile)
		sub, err := dm.typeHash(t.Type, depthBudget, cache)
		if err != nil {
			return 0, err
		}
		maphash.WriteComparable(h, sub)
	case *Const:
		maphash.WriteComparable(h, kindConst)
		sub, err := dm.typeHash(t.Type, depthBudget, cache)
		if err != nil {
			return 0, err
		}
		maphash.WriteComparable(h, sub)
	case *Restrict:
		maphash.WriteComparable(h, kindRestrict)
		sub, err := dm.typeHash(t.Type, depthBudget, cache)
		if err != nil {
			return 0, err
		}
		maphash.WriteComparable(h, sub)
	case *Func:
		maphash.WriteComparable(h, kindFunc)
		maphash.WriteComparable(h, t.Name)
		sub, err := dm.typeHash(t.Type, depthBudget, cache)
		if err != nil {
			return 0, err
		}
		maphash.WriteComparable(h, sub)
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
			sub, err := dm.typeHash(p.Type, depthBudget, cache)
			if err != nil {
				return 0, err
			}
			maphash.WriteComparable(h, sub)
		}
		sub, err := dm.typeHash(t.Return, depthBudget, cache)
		if err != nil {
			return 0, err
		}
		maphash.WriteComparable(h, sub)
	case *Var:
		maphash.WriteComparable(h, kindVar)
		maphash.WriteComparable(h, t.Name)
		maphash.WriteComparable(h, t.Linkage)
		sub, err := dm.typeHash(t.Type, depthBudget, cache)
		if err != nil {
			return 0, err
		}
		maphash.WriteComparable(h, sub)
	case *Datasec:
		maphash.WriteComparable(h, kindDatasec)
		maphash.WriteComparable(h, t.Name)
		for _, v := range t.Vars {
			maphash.WriteComparable(h, v.Offset)
			maphash.WriteComparable(h, v.Size)
			sub, err := dm.typeHash(v.Type, depthBudget, cache)
			if err != nil {
				return 0, err
			}
			maphash.WriteComparable(h, sub)
		}
	case *declTag:
		maphash.WriteComparable(h, kindDeclTag)
		maphash.WriteComparable(h, t.Value)
		maphash.WriteComparable(h, t.Index)
		sub, err := dm.typeHash(t.Type, depthBudget, cache)
		if err != nil {
			return 0, err
		}
		maphash.WriteComparable(h, sub)
	case *TypeTag:
		maphash.WriteComparable(h, kindTypeTag)
		maphash.WriteComparable(h, t.Value)
		sub, err := dm.typeHash(t.Type, depthBudget, cache)
		if err != nil {
			return 0, err
		}
		maphash.WriteComparable(h, sub)
	case *Float:
		maphash.WriteComparable(h, kindFloat)
		maphash.WriteComparable(h, *t)
	default:
		return 0, fmt.Errorf("unsupported type for hashing: %T", t)
	}

	return h.Sum64(), nil
}

type typKey struct {
	a Type
	b Type
}

var errNotEquivalent = errors.New("types are not equivalent")

// typesEquivalent checks if two types are functionally equivalent.
func typesEquivalent(aTyp, b Type, visited []Type, cache map[typKey]bool) error {
	// Fast path: do a pointer comparison, if they are identical then they are also equivalent.
	if aTyp == b {
		return nil
	}

	switch a := aTyp.(type) {
	case *Void:
		if _, ok := b.(*Void); ok {
			return nil
		}
		return errNotEquivalent
	case *Int:
		b, ok := b.(*Int)
		if !ok {
			return errNotEquivalent
		}
		if a.Name != b.Name || a.Size != b.Size || a.Encoding != b.Encoding {
			return errNotEquivalent
		}
		return nil
	case *Enum:
		b, ok := b.(*Enum)
		if !ok {
			return errNotEquivalent
		}
		if a.Name != b.Name || len(a.Values) != len(b.Values) {
			return errNotEquivalent
		}
		for i := range a.Values {
			if a.Values[i].Name != b.Values[i].Name || a.Values[i].Value != b.Values[i].Value {
				return errNotEquivalent
			}
		}
		return nil
	case *Fwd:
		b, ok := b.(*Fwd)
		if !ok {
			return errNotEquivalent
		}
		if a.Name != b.Name || a.Kind != b.Kind {
			return errNotEquivalent
		}
		return nil
	case *Float:
		b, ok := b.(*Float)
		if !ok {
			return errNotEquivalent
		}
		if a.Name != b.Name || a.Size != b.Size {
			return errNotEquivalent
		}
		return nil
	case *Array:
		b, ok := b.(*Array)
		if !ok {
			return errNotEquivalent
		}

		if a.Nelems != b.Nelems {
			return errNotEquivalent
		}
		if err := typesEquivalent(a.Index, b.Index, visited, cache); err != nil {
			return err
		}
		if err := typesEquivalent(a.Type, b.Type, visited, cache); err != nil {
			return err
		}
		return nil
	case *Pointer:
		b, ok := b.(*Pointer)
		if !ok {
			return errNotEquivalent
		}

		// Detect cycles by tracking visited types. Assume types are equivalent if we have already
		// visited this type in the current equivalence check.
		if slices.Contains(visited, aTyp) {
			return nil
		}
		visited = append(visited, aTyp)

		return typesEquivalent(a.Target, b.Target, visited, cache)
	case *Struct, *Union:
		// Use a cache to avoid recomputation. We only do this for composite types since they are
		// where types fan out the most. For other types, the overhead of the lookup and update
		// outweighs performance benefits.
		cacheKey := typKey{a: aTyp, b: b}
		if equal, ok := cache[cacheKey]; ok {
			if equal {
				return nil
			}
			return errNotEquivalent
		}

		compErr := compositeEquivalent(aTyp, b, visited, cache)
		cache[cacheKey] = compErr == nil
		return compErr
	case *Typedef:
		b, ok := b.(*Typedef)
		if !ok {
			return errNotEquivalent
		}
		if a.Name != b.Name {
			return errNotEquivalent
		}
		return typesEquivalent(a.Type, b.Type, visited, cache)
	case *Volatile:
		b, ok := b.(*Volatile)
		if !ok {
			return errNotEquivalent
		}
		return typesEquivalent(a.Type, b.Type, visited, cache)
	case *Const:
		b, ok := b.(*Const)
		if !ok {
			return errNotEquivalent
		}
		return typesEquivalent(a.Type, b.Type, visited, cache)
	case *Restrict:
		b, ok := b.(*Restrict)
		if !ok {
			return errNotEquivalent
		}
		return typesEquivalent(a.Type, b.Type, visited, cache)
	case *Func:
		b, ok := b.(*Func)
		if !ok {
			return errNotEquivalent
		}
		if a.Name != b.Name {
			return errNotEquivalent
		}
		return typesEquivalent(a.Type, b.Type, visited, cache)
	case *FuncProto:
		b, ok := b.(*FuncProto)
		if !ok {
			return errNotEquivalent
		}

		if err := typesEquivalent(a.Return, b.Return, visited, cache); err != nil {
			return err
		}
		if len(a.Params) != len(b.Params) {
			return errNotEquivalent
		}
		for i := range a.Params {
			if a.Params[i].Name != b.Params[i].Name {
				return errNotEquivalent
			}
			if err := typesEquivalent(a.Params[i].Type, b.Params[i].Type, visited, cache); err != nil {
				return err
			}
		}
		return nil
	case *Var:
		b, ok := b.(*Var)
		if !ok {
			return errNotEquivalent
		}
		if a.Name != b.Name {
			return errNotEquivalent
		}
		if err := typesEquivalent(a.Type, b.Type, visited, cache); err != nil {
			return err
		}
		if a.Linkage != b.Linkage {
			return errNotEquivalent
		}
		return nil
	case *Datasec:
		b, ok := b.(*Datasec)
		if !ok {
			return errNotEquivalent
		}
		if a.Name != b.Name || len(a.Vars) != len(b.Vars) {
			return errNotEquivalent
		}
		for i := range a.Vars {
			if a.Vars[i].Offset != b.Vars[i].Offset ||
				a.Vars[i].Size != b.Vars[i].Size {
				return errNotEquivalent
			}

			if err := typesEquivalent(a.Vars[i].Type, b.Vars[i].Type, visited, cache); err != nil {
				return err
			}
		}
		return nil
	case *declTag:
		b, ok := b.(*declTag)
		if !ok {
			return errNotEquivalent
		}
		if a.Value != b.Value || a.Index != b.Index {
			return errNotEquivalent
		}
		return typesEquivalent(a.Type, b.Type, visited, cache)
	case *TypeTag:
		b, ok := b.(*TypeTag)
		if !ok {
			return errNotEquivalent
		}
		if a.Value != b.Value {
			return errNotEquivalent
		}
		if err := typesEquivalent(a.Type, b.Type, visited, cache); err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unsupported type for equivalence: %T", a)
	}
}

func compositeEquivalent(aTyp, b Type, visited []Type, cache map[typKey]bool) error {
	var membersA, membersB []Member
	switch a := aTyp.(type) {
	case *Struct:
		b, ok := b.(*Struct)
		if !ok {
			return errNotEquivalent
		}

		if a.Name != b.Name || a.Size != b.Size || len(a.Members) != len(b.Members) {
			return errNotEquivalent
		}
		membersA = a.Members
		membersB = b.Members
	case *Union:
		b, ok := b.(*Union)
		if !ok {
			return errNotEquivalent
		}

		if a.Name != b.Name || a.Size != b.Size || len(a.Members) != len(b.Members) {
			return errNotEquivalent
		}
		membersA = a.Members
		membersB = b.Members
	}

	for i := range membersA {
		if membersA[i].Name != membersB[i].Name || membersA[i].Offset != membersB[i].Offset {
			return errNotEquivalent
		}

		if err := typesEquivalent(membersA[i].Type, membersB[i].Type, visited, cache); err != nil {
			return err
		}
	}

	return nil
}
