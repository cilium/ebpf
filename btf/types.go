package btf

import (
	"fmt"
	"math"
	"strings"

	"github.com/pkg/errors"
)

type Type interface {
	String() string

	// Prevent other packages from implementing Type
	dummy()
}

type Name string

func (n Name) String() string {
	if n == "" {
		return "(anon)"
	}
	return string(n)
}

type Void struct{}

func (v Void) String() string { return "void" }
func (v Void) dummy()         {}

type Int struct {
	Name
	Size uint32
}

func (i *Int) size() uint32 { return i.Size }
func (i *Int) dummy()       {}

type Pointer struct {
	Target Type
}

func (p *Pointer) String() string { return "*" + p.Target.String() }
func (p *Pointer) size() uint32   { return 8 }
func (p *Pointer) dummy()         {}

type Array struct {
	Type   Type
	Nelems uint32
}

func (arr *Array) String() string { return fmt.Sprintf("%v[%d]", arr.Type, arr.Nelems) }
func (arr *Array) dummy()         {}

type Struct struct {
	Name
	Size    uint32
	Members []Member
}

func (s *Struct) String() string {
	// Stringifying members is not safe, because they may contain cycles.
	return fmt.Sprintf("struct %v", s.Name)
}

func (s *Struct) size() uint32 { return s.Size }
func (s *Struct) dummy()       {}

type Union struct {
	Name
	Size    uint32
	Members []Member
}

func (u *Union) String() string {
	// Stringifying members is not safe, because they may contain cycles.
	return fmt.Sprintf("union %v ", u.Name)
}

func (u *Union) size() uint32 { return u.Size }
func (u *Union) dummy()       {}

type Member struct {
	Name
	Type   Type
	Offset uint32
}

func (m *Member) String() string {
	return fmt.Sprintf("%s %v", m.Name, m.Type)
}

type Enum struct {
	Name
}

func (e *Enum) String() string { return "enum " + e.Name.String() }
func (e *Enum) size() uint32   { return 4 }
func (e *Enum) dummy()         {}

type Fwd struct {
	Name
}

func (f *Fwd) dummy() {}

type Typedef struct {
	Name
	Type Type
}

func (td *Typedef) String() string { return td.Name.String() }
func (td *Typedef) dummy()         {}

type Volatile struct {
	Type Type
}

func (v *Volatile) String() string { return "volatile " + v.Type.String() }
func (v *Volatile) dummy()         {}

type Const struct {
	Type Type
}

func (c *Const) String() string { return "const " + c.Type.String() }
func (c *Const) dummy()         {}

type Restrict struct {
	Type Type
}

func (r *Restrict) String() string { return "restrict " + r.Type.String() }
func (r *Restrict) dummy()         {}

type Func struct {
	Name
	Type Type
}

func (f *Func) String() string { return f.Name.String() + " " + f.Type.String() }
func (f *Func) dummy()         {}

type FuncProto struct {
	Return Type
}

func (fp *FuncProto) String() string { return fmt.Sprintf("func(...) %v", fp.Return) }
func (fp *FuncProto) dummy()         {}

type Var struct {
	Name
	Type Type
}

func (v *Var) dummy() {}

type Datasec struct {
	Name
	Size uint32
}

func (ds *Datasec) size() uint32 { return ds.Size }
func (ds *Datasec) dummy()       {}

type sized interface {
	size() uint32
}

var (
	_ sized = (*Int)(nil)
	_ sized = (*Pointer)(nil)
	_ sized = (*Struct)(nil)
	_ sized = (*Union)(nil)
	_ sized = (*Enum)(nil)
	_ sized = (*Datasec)(nil)
)

// Sizeof returns the size of a type in bytes.
//
// Returns a negative number if the size can't be computed.
func Sizeof(typ Type) int {
	const maxDepth = 10

	var (
		n    = int64(1)
		elem int64
	)
	for i := 0; i < maxDepth; i++ {
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

		case sized:
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

func inflateRawTypes(rawTypes []rawType, strings map[uint32]string) (_ map[string][]Type, err error) {
	defer recoverError(&err)

	var (
		byID     = make(map[btfTypeID]Type, len(rawTypes))
		pointers = make(map[btfTypeID]*Pointer)
		typeByID func(btfTypeID) Type
		visited  typeStack
	)

	// Pre-populate "void"
	byID[0] = Void{}

	nameByOffset := func(offset uint32) Name {
		str, ok := strings[offset]
		if !ok {
			panic(errors.Errorf("no string at offset %d", offset))
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

	typeByID = func(id btfTypeID) Type {
		const maxDepth = 10

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

		if len(visited) > maxDepth {
			panic(errors.Errorf("exceeded maximum depth: %v", visited))
		}

		switch raw.Kind() {
		case kindInt:
			typ = &Int{name, raw.Size()}

		case kindPointer:
			// structs and unions may have members which are pointers
			// to themselves.
			//    struct foo { struct foo *next; }
			//    KIND_STRUCT -> KIND_PTR -> KIND_STRUCT
			//    KIND_PTR -> KIND_STRUCT -> KIND_PTR
			// Collect them here, and resolve them later.
			ptr := &Pointer{}
			pointers[raw.Type()] = ptr
			typ = ptr

		case kindArray:
			arr := raw.data.(*btfArray)

			// IndexType is unused according to btf.rst.
			// Try to resolve it, but don't make it available
			// right now.
			_ = typeByID(arr.IndexType)

			typ = &Array{
				Type:   typeByID(arr.Type),
				Nelems: arr.Nelems,
			}

		case kindStruct:
			typ = &Struct{name, raw.Size(), convertMembers(raw.data.([]btfMember))}

		case kindUnion:
			typ = &Union{name, raw.Size(), convertMembers(raw.data.([]btfMember))}

		case kindEnum:
			typ = &Enum{name}

		case kindForward:
			typ = &Fwd{name}

		case kindTypedef:
			typ = &Typedef{name, typeByID(raw.Type())}

		case kindVolatile:
			typ = &Volatile{typeByID(raw.Type())}

		case kindConst:
			typ = &Const{typeByID(raw.Type())}

		case kindRestrict:
			typ = &Restrict{typeByID(raw.Type())}

		case kindFunc:
			// TODO: Check that Type is a FuncProto?
			typ = &Func{name, typeByID(raw.Type())}

		case kindFuncProto:
			typ = &FuncProto{typeByID(raw.Type())}

		case kindVar:
			typ = &Var{name, typeByID(raw.Type())}

		case kindDatasec:
			typ = &Datasec{name, raw.SizeType}

		default:
			panic(errors.Errorf("type id %d: unknown kind: %v", id, raw.Kind()))
		}

		byID[id] = typ
		return typ
	}

	types := make(map[string][]Type, len(rawTypes))
	for i, raw := range rawTypes {
		typ := typeByID(btfTypeID(i + 1))
		name := strings[raw.NameOff]
		if name == "" {
			continue
		}
		types[name] = append(types[name], typ)
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
	id   btfTypeID
	name Name
}

func (ts typeStack) String() string {
	var str []string
	for _, entry := range ts {
		str = append(str, fmt.Sprintf("%v (%d)", entry.name, entry.id))
	}
	return strings.Join(str, " ➞ ")
}

func (ts *typeStack) contains(id btfTypeID) bool {
	for _, have := range *ts {
		if have.id == id {
			return true
		}
	}
	return false
}

func (ts *typeStack) push(id btfTypeID, name Name) {
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
