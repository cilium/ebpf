package btf

import (
	"fmt"
	"math"
	"strings"

	"github.com/pkg/errors"
)

const maxTypeDepth = 32

// TypeID identifies a type in a BTF section.
type TypeID uint32

// ID implements part of the Type interface.
func (tid TypeID) ID() TypeID {
	return tid
}

// Type represents a type described by BTF.
type Type interface {
	String() string
	ID() TypeID

	// Make a shallow copy of the type. If the type
	// contains other Types, mark them for later copying.
	copy(*copyStack) Type
}

// Name identifies a type.
//
// Anonymous types have an empty name.
type Name string

func (n Name) String() string {
	if n == "" {
		return "(anon)"
	}
	return string(n)
}

func (n Name) name() string {
	return string(n)
}

// Void is the unit type of BTF.
type Void struct{}

func (v Void) String() string         { return "void" }
func (v Void) ID() TypeID             { return 0 }
func (v Void) copy(_ *copyStack) Type { return Void{} }

// Int is an integer of a given length.
type Int struct {
	TypeID
	Name

	// The size of the integer in bytes.
	Size uint32
}

func (i *Int) size() uint32 { return i.Size }
func (i *Int) copy(_ *copyStack) Type {
	cpy := *i
	return &cpy
}

// Pointer is a pointer to another type.
type Pointer struct {
	TypeID
	Target Type
}

func (p *Pointer) String() string { return "*" + p.Target.String() }
func (p *Pointer) size() uint32   { return 8 }
func (p *Pointer) copy(cs *copyStack) Type {
	cpy := *p
	cs.push(&cpy.Target)
	return &cpy
}

// Array is an array with a fixed number of elements.
type Array struct {
	TypeID
	Type   Type
	Nelems uint32
}

func (arr *Array) String() string { return fmt.Sprintf("%v[%d]", arr.Type, arr.Nelems) }
func (arr *Array) copy(cs *copyStack) Type {
	cpy := *arr
	cs.push(&cpy.Type)
	return &cpy
}

// Struct is a compound type of consecutive members.
type Struct struct {
	TypeID
	Name
	// The size of the struct including padding, in bytes
	Size    uint32
	Members []Member
}

func (s *Struct) String() string {
	// Stringifying members is not safe, because they may contain cycles.
	return fmt.Sprintf("struct %v", s.Name)
}

func (s *Struct) size() uint32 { return s.Size }
func (s *Struct) copy(cs *copyStack) Type {
	cpy := *s
	cpy.Members = copyMembers(cs, cpy.Members)
	return &cpy
}

// Union is a compound type where members occupy the same memory.
type Union struct {
	TypeID
	Name
	// The size of the union including padding, in bytes.
	Size    uint32
	Members []Member
}

func (u *Union) String() string {
	// Stringifying members is not safe, because they may contain cycles.
	return fmt.Sprintf("union %v ", u.Name)
}

func (u *Union) size() uint32 { return u.Size }
func (u *Union) copy(cs *copyStack) Type {
	cpy := *u
	cpy.Members = copyMembers(cs, cpy.Members)
	return &cpy
}

// Member is part of a Struct or Union.
//
// It is not a valid Type.
type Member struct {
	Name
	Type   Type
	Offset uint32
}

func (m *Member) String() string {
	return fmt.Sprintf("%s %v", m.Name, m.Type)
}

func copyMembers(cs *copyStack, in []Member) []Member {
	cpy := make([]Member, 0, len(in))
	for i, member := range in {
		cpy = append(cpy, member)
		cs.push(&cpy[i].Type)
	}
	return cpy
}

// Enum lists possible values.
type Enum struct {
	TypeID
	Name
}

func (e *Enum) String() string { return "enum " + e.Name.String() }
func (e *Enum) size() uint32   { return 4 }
func (e *Enum) copy(_ *copyStack) Type {
	cpy := *e
	return &cpy
}

// Fwd is a forward declaration of a Type.
type Fwd struct {
	TypeID
	Name
}

func (f *Fwd) copy(_ *copyStack) Type {
	cpy := *f
	return &cpy
}

// Typedef is an alias of a Type.
type Typedef struct {
	TypeID
	Name
	Type Type
}

func (td *Typedef) String() string { return td.Name.String() }
func (td *Typedef) copy(cs *copyStack) Type {
	cpy := *td
	cs.push(&cpy.Type)
	return &cpy
}

// Volatile is a modifier.
type Volatile struct {
	TypeID
	Type Type
}

func (v *Volatile) String() string { return "volatile " + v.Type.String() }
func (v *Volatile) copy(cs *copyStack) Type {
	cpy := *v
	cs.push(&cpy.Type)
	return &cpy
}

// Const is a modifier.
type Const struct {
	TypeID
	Type Type
}

func (c *Const) String() string { return "const " + c.Type.String() }
func (c *Const) copy(cs *copyStack) Type {
	cpy := *c
	cs.push(&cpy.Type)
	return &cpy
}

// Restrict is a modifier.
type Restrict struct {
	TypeID
	Type Type
}

func (r *Restrict) String() string { return "restrict " + r.Type.String() }
func (r *Restrict) copy(cs *copyStack) Type {
	cpy := *r
	cs.push(&cpy.Type)
	return &cpy
}

// Func is a function definition.
type Func struct {
	TypeID
	Name
	Type Type
}

func (f *Func) String() string { return f.Name.String() + " " + f.Type.String() }
func (f *Func) copy(cs *copyStack) Type {
	cpy := *f
	cs.push(&cpy.Type)
	return &cpy
}

// FuncProto is a function declaration.
type FuncProto struct {
	TypeID
	Return Type
}

func (fp *FuncProto) String() string { return fmt.Sprintf("func(...) %v", fp.Return) }
func (fp *FuncProto) copy(cs *copyStack) Type {
	cpy := *fp
	cs.push(&cpy.Return)
	return &cpy
}

// Var is a global variable.
type Var struct {
	TypeID
	Name
	Type Type
}

func (v *Var) copy(cs *copyStack) Type {
	cpy := *v
	cs.push(&cpy.Type)
	return &cpy
}

// Datasec is a global program section containing data.
type Datasec struct {
	TypeID
	Name
	Size uint32
}

func (ds *Datasec) size() uint32 { return ds.Size }
func (ds *Datasec) copy(_ *copyStack) Type {
	cpy := *ds
	return &cpy
}

type sizer interface {
	size() uint32
}

var (
	_ sizer = (*Int)(nil)
	_ sizer = (*Pointer)(nil)
	_ sizer = (*Struct)(nil)
	_ sizer = (*Union)(nil)
	_ sizer = (*Enum)(nil)
	_ sizer = (*Datasec)(nil)
)

// Sizeof returns the size of a type in bytes.
//
// Returns a negative number if the size can't be computed.
func Sizeof(typ Type) int {
	var (
		n    = int64(1)
		elem int64
	)

	for i := 0; i < maxTypeDepth; i++ {
		switch v := typ.(type) {
		case *Array:
			if n > 0 && int64(v.Nelems) > math.MaxInt64/n {
				return -1
			}

			// Arrays may be of zero length, which allows
			// n to be zero as well.
			n *= int64(v.Nelems)
			typ = v.Type
			continue

		case sizer:
			elem = int64(v.size())

		case *Typedef:
			typ = v.Type
			continue
		case *Volatile:
			typ = v.Type
			continue
		case *Const:
			typ = v.Type
			continue
		case *Restrict:
			typ = v.Type
			continue

		default:
			return -1
		}

		if n > 0 && elem > math.MaxInt64/n {
			return -1
		}

		size := n * elem
		if int64(int(size)) != size {
			return -1
		}

		return int(size)
	}

	return -1
}

// copy a Type recursively.
//
// typ may form a cycle.
func copyType(typ Type) Type {
	var (
		copies = make(map[Type]Type)
		work   copyStack
	)

	for t := &typ; t != nil; t = work.pop() {
		// *t is the identity of the type.
		if cpy := copies[*t]; cpy != nil {
			*t = cpy
			continue
		}

		// The call to copy() will push items onto
		// work if needed.
		cpy := (*t).copy(&work)
		copies[*t] = cpy
		*t = cpy
	}

	return typ
}

// copyStack keeps track of pointers to types which still
// need to be copied.
type copyStack []*Type

// push adds a type to the stack.
func (cs *copyStack) push(t *Type) {
	*cs = append(*cs, t)
}

// pop returns the topmost Type, or nil.
func (cs *copyStack) pop() *Type {
	n := len(*cs)
	if n == 0 {
		return nil
	}

	t := (*cs)[n-1]
	*cs = (*cs)[:n-1]
	return t
}

type namer interface {
	name() string
}

var _ namer = Name("")

func inflateRawTypes(rawTypes []rawType, strings stringTable) (_ map[string][]Type, err error) {
	defer recoverError(&err)

	var (
		byID     = make(map[TypeID]Type, len(rawTypes))
		pointers = make(map[TypeID]*Pointer)
		typeByID func(TypeID) Type
		visited  typeStack
	)

	// Pre-populate "void"
	byID[0] = Void{}

	nameByOffset := func(offset uint32) Name {
		str, err := strings.Lookup(offset)
		if err != nil {
			panic(err)
		}

		return Name(str)
	}

	convertMembers := func(raw []btfMember) []Member {
		members := make([]Member, 0, len(raw))
		for _, member := range raw {
			members = append(members, Member{
				Name:   nameByOffset(member.NameOff),
				Type:   typeByID(member.Type),
				Offset: member.Offset,
			})
		}
		return members
	}

	typeByID = func(id TypeID) Type {
		typ, ok := byID[id]
		if ok {
			return typ
		}

		if int(id-1) >= len(rawTypes) {
			panic(errors.Errorf("invalid type id %d", id))
		}

		var (
			raw  = rawTypes[int(id-1)]
			name = nameByOffset(raw.NameOff)
		)

		if visited.contains(id) {
			panic(errors.Errorf("circular type %v %d: %v", name, id, visited))
		}

		visited.push(id, name)
		defer visited.pop()

		if len(visited) > maxTypeDepth {
			panic(errors.Errorf("exceeded maximum depth: %v", visited))
		}

		switch raw.Kind() {
		case kindInt:
			typ = &Int{id, name, raw.Size()}

		case kindPointer:
			// structs and unions may have members which are pointers
			// to themselves.
			//    struct foo { struct foo *next; }
			//    KIND_STRUCT -> KIND_PTR -> KIND_STRUCT
			//    KIND_PTR -> KIND_STRUCT -> KIND_PTR
			// Collect them here, and resolve them later.
			ptr := &Pointer{TypeID: id}
			pointers[raw.Type()] = ptr
			typ = ptr

		case kindArray:
			arr := raw.data.(*btfArray)

			// IndexType is unused according to btf.rst.
			// Try to resolve it, but don't make it available
			// right now.
			_ = typeByID(arr.IndexType)

			typ = &Array{
				TypeID: id,
				Type:   typeByID(arr.Type),
				Nelems: arr.Nelems,
			}

		case kindStruct:
			typ = &Struct{id, name, raw.Size(), convertMembers(raw.data.([]btfMember))}

		case kindUnion:
			typ = &Union{id, name, raw.Size(), convertMembers(raw.data.([]btfMember))}

		case kindEnum:
			typ = &Enum{id, name}

		case kindForward:
			typ = &Fwd{id, name}

		case kindTypedef:
			typ = &Typedef{id, name, typeByID(raw.Type())}

		case kindVolatile:
			typ = &Volatile{id, typeByID(raw.Type())}

		case kindConst:
			typ = &Const{id, typeByID(raw.Type())}

		case kindRestrict:
			typ = &Restrict{id, typeByID(raw.Type())}

		case kindFunc:
			// TODO: Check that Type is a FuncProto?
			typ = &Func{id, name, typeByID(raw.Type())}

		case kindFuncProto:
			typ = &FuncProto{id, typeByID(raw.Type())}

		case kindVar:
			typ = &Var{id, name, typeByID(raw.Type())}

		case kindDatasec:
			typ = &Datasec{id, name, raw.SizeType}

		default:
			panic(errors.Errorf("type id %d: unknown kind: %v", id, raw.Kind()))
		}

		byID[id] = typ
		return typ
	}

	types := make(map[string][]Type, len(rawTypes))
	for i := range rawTypes {
		id := TypeID(i + 1)
		typ := typeByID(id)

		if namer, ok := typ.(namer); ok && namer.name() != "" {
			name := namer.name()
			types[name] = append(types[name], typ)
		}
	}

	for id, pointer := range pointers {
		target, ok := byID[id]
		if !ok {
			return nil, errors.Errorf("can't resolve pointer to type id %d", id)
		}

		pointer.Target = target
	}

	return types, nil
}

type typeStack []typeStackEntry

type typeStackEntry struct {
	id   TypeID
	name Name
}

func (ts typeStack) String() string {
	var str []string
	for _, entry := range ts {
		str = append(str, fmt.Sprintf("%v (%d)", entry.name, entry.id))
	}
	return strings.Join(str, " ➞ ")
}

func (ts *typeStack) contains(id TypeID) bool {
	for _, have := range *ts {
		if have.id == id {
			return true
		}
	}
	return false
}

func (ts *typeStack) push(id TypeID, name Name) {
	*ts = append(*ts, typeStackEntry{id, name})
}

func (ts *typeStack) pop() {
	*ts = (*ts)[:len(*ts)-1]
}

func recoverError(err *error) {
	r := recover()
	if r == nil {
		return
	}

	if rerr, ok := r.(error); ok {
		*err = rerr
		return
	}

	*err = errors.Errorf("function panicked: %v", r)
}
