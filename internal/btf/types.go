package btf

import (
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
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
	// Type can be formatted using the %s and %v verbs. %s outputs only the
	// identity of the type, without any detail. %v outputs additional detail.
	//
	// Use the '+' flag to include the address of the type.
	//
	// Use the width to specify how many levels of detail to output, for example
	// %1v will output detail for the root type and a short description of its
	// children. %2v would output details of the root type and its children
	// as well as a short description of the grandchildren.
	fmt.Formatter

	// The type ID of the Type within this BTF spec.
	ID() TypeID

	// Name of the type, empty for anonymous types and types that cannot
	// carry a name, like Void and Pointer.
	TypeName() string

	// Make a copy of the type, without copying Type members.
	copy() Type

	// Enumerate all nested Types. Repeated calls must visit nested
	// types in the same order.
	walk(*typeDeque)
}

var (
	_ Type = (*Int)(nil)
	_ Type = (*Struct)(nil)
	_ Type = (*Union)(nil)
	_ Type = (*Enum)(nil)
	_ Type = (*Fwd)(nil)
	_ Type = (*Func)(nil)
	_ Type = (*Typedef)(nil)
	_ Type = (*Var)(nil)
	_ Type = (*Datasec)(nil)
	_ Type = (*Float)(nil)
)

// Void is the unit type of BTF.
type Void struct{}

func (v *Void) ID() TypeID                     { return 0 }
func (v *Void) Format(fs fmt.State, verb rune) { formatType(fs, verb, v) }
func (v *Void) TypeName() string               { return "" }
func (v *Void) size() uint32                   { return 0 }
func (v *Void) copy() Type                     { return (*Void)(nil) }
func (v *Void) walk(*typeDeque)                {}

type IntEncoding byte

const (
	Signed IntEncoding = 1 << iota
	Char
	Bool
)

func (ie IntEncoding) IsSigned() bool {
	return ie&Signed != 0
}

func (ie IntEncoding) IsChar() bool {
	return ie&Char != 0
}

func (ie IntEncoding) IsBool() bool {
	return ie&Bool != 0
}

func (ie IntEncoding) String() string {
	switch {
	case ie.IsChar() && ie.IsSigned():
		return "char"
	case ie.IsChar() && !ie.IsSigned():
		return "uchar"
	case ie.IsBool():
		return "bool"
	case ie.IsSigned():
		return "signed"
	default:
		return "unsigned"
	}
}

// Int is an integer of a given length.
type Int struct {
	TypeID

	Name string

	// The size of the integer in bytes.
	Size     uint32
	Encoding IntEncoding
	// OffsetBits is the starting bit offset. Currently always 0.
	// See https://www.kernel.org/doc/html/latest/bpf/btf.html#btf-kind-int
	OffsetBits uint32
	Bits       byte
}

func (i *Int) Format(fs fmt.State, verb rune) {
	extra := []interface{}{
		i.Encoding,
		"size=", i.Size * 8,
	}
	if i.Bits > 0 {
		extra = append(extra, "bits=", i.Bits)
	}
	formatType(fs, verb, i, extra...)
}

func (i *Int) TypeName() string { return i.Name }
func (i *Int) size() uint32     { return i.Size }
func (i *Int) walk(*typeDeque)  {}
func (i *Int) copy() Type {
	cpy := *i
	return &cpy
}

func (i *Int) isBitfield() bool {
	return i.OffsetBits > 0
}

// Pointer is a pointer to another type.
type Pointer struct {
	TypeID
	Target Type
}

func (p *Pointer) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, p, "target=", p.Target)
}

func (p *Pointer) TypeName() string    { return "" }
func (p *Pointer) size() uint32        { return 8 }
func (p *Pointer) walk(tdq *typeDeque) { tdq.push(&p.Target) }
func (p *Pointer) copy() Type {
	cpy := *p
	return &cpy
}

// Array is an array with a fixed number of elements.
type Array struct {
	TypeID
	Type   Type
	Nelems uint32
}

func (arr *Array) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, arr, "type=", arr.Type, "n=", arr.Nelems)
}

func (arr *Array) TypeName() string { return "" }

func (arr *Array) walk(tdq *typeDeque) { tdq.push(&arr.Type) }
func (arr *Array) copy() Type {
	cpy := *arr
	return &cpy
}

// Struct is a compound type of consecutive members.
type Struct struct {
	TypeID
	Name string
	// The size of the struct including padding, in bytes
	Size    uint32
	Members []Member
}

func (s *Struct) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, s, "fields=", len(s.Members))
}

func (s *Struct) TypeName() string { return s.Name }

func (s *Struct) size() uint32 { return s.Size }

func (s *Struct) walk(tdq *typeDeque) {
	for i := range s.Members {
		tdq.push(&s.Members[i].Type)
	}
}

func (s *Struct) copy() Type {
	cpy := *s
	cpy.Members = copyMembers(s.Members)
	return &cpy
}

func (s *Struct) members() []Member {
	return s.Members
}

// Union is a compound type where members occupy the same memory.
type Union struct {
	TypeID
	Name string
	// The size of the union including padding, in bytes.
	Size    uint32
	Members []Member
}

func (u *Union) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, u, "fields=", len(u.Members))
}

func (u *Union) TypeName() string { return u.Name }

func (u *Union) size() uint32 { return u.Size }

func (u *Union) walk(tdq *typeDeque) {
	for i := range u.Members {
		tdq.push(&u.Members[i].Type)
	}
}

func (u *Union) copy() Type {
	cpy := *u
	cpy.Members = copyMembers(u.Members)
	return &cpy
}

func (u *Union) members() []Member {
	return u.Members
}

func copyMembers(orig []Member) []Member {
	cpy := make([]Member, len(orig))
	copy(cpy, orig)
	return cpy
}

type composite interface {
	members() []Member
}

var (
	_ composite = (*Struct)(nil)
	_ composite = (*Union)(nil)
)

// Member is part of a Struct or Union.
//
// It is not a valid Type.
type Member struct {
	Name string
	Type Type
	// OffsetBits is the bit offset of this member.
	OffsetBits   uint32
	BitfieldSize uint32
}

// Enum lists possible values.
type Enum struct {
	TypeID
	Name   string
	Values []EnumValue
}

func (e *Enum) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, e, "values=", len(e.Values))
}

func (e *Enum) TypeName() string { return e.Name }

// EnumValue is part of an Enum
//
// Is is not a valid Type
type EnumValue struct {
	Name  string
	Value int32
}

func (e *Enum) size() uint32    { return 4 }
func (e *Enum) walk(*typeDeque) {}
func (e *Enum) copy() Type {
	cpy := *e
	cpy.Values = make([]EnumValue, len(e.Values))
	copy(cpy.Values, e.Values)
	return &cpy
}

// FwdKind is the type of forward declaration.
type FwdKind int

// Valid types of forward declaration.
const (
	FwdStruct FwdKind = iota
	FwdUnion
)

func (fk FwdKind) String() string {
	switch fk {
	case FwdStruct:
		return "struct"
	case FwdUnion:
		return "union"
	default:
		return fmt.Sprintf("%T(%d)", fk, int(fk))
	}
}

// Fwd is a forward declaration of a Type.
type Fwd struct {
	TypeID
	Name string
	Kind FwdKind
}

func (f *Fwd) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, f, f.Kind)
}

func (f *Fwd) TypeName() string { return f.Name }

func (f *Fwd) walk(*typeDeque) {}
func (f *Fwd) copy() Type {
	cpy := *f
	return &cpy
}

// Typedef is an alias of a Type.
type Typedef struct {
	TypeID
	Name string
	Type Type
}

func (td *Typedef) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, td, td.Type)
}

func (td *Typedef) TypeName() string { return td.Name }

func (td *Typedef) walk(tdq *typeDeque) { tdq.push(&td.Type) }
func (td *Typedef) copy() Type {
	cpy := *td
	return &cpy
}

// Volatile is a qualifier.
type Volatile struct {
	TypeID
	Type Type
}

func (v *Volatile) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, v, v.Type)
}

func (v *Volatile) TypeName() string { return "" }

func (v *Volatile) qualify() Type       { return v.Type }
func (v *Volatile) walk(tdq *typeDeque) { tdq.push(&v.Type) }
func (v *Volatile) copy() Type {
	cpy := *v
	return &cpy
}

// Const is a qualifier.
type Const struct {
	TypeID
	Type Type
}

func (c *Const) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, c, c.Type)
}

func (c *Const) TypeName() string { return "" }

func (c *Const) qualify() Type       { return c.Type }
func (c *Const) walk(tdq *typeDeque) { tdq.push(&c.Type) }
func (c *Const) copy() Type {
	cpy := *c
	return &cpy
}

// Restrict is a qualifier.
type Restrict struct {
	TypeID
	Type Type
}

func (r *Restrict) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, r, r.Type)
}

func (r *Restrict) TypeName() string { return "" }

func (r *Restrict) qualify() Type       { return r.Type }
func (r *Restrict) walk(tdq *typeDeque) { tdq.push(&r.Type) }
func (r *Restrict) copy() Type {
	cpy := *r
	return &cpy
}

// Func is a function definition.
type Func struct {
	TypeID
	Name    string
	Type    Type
	Linkage FuncLinkage
}

func (f *Func) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, f, f.Linkage, "proto=", f.Type)
}

func (f *Func) TypeName() string { return f.Name }

func (f *Func) walk(tdq *typeDeque) { tdq.push(&f.Type) }
func (f *Func) copy() Type {
	cpy := *f
	return &cpy
}

// FuncProto is a function declaration.
type FuncProto struct {
	TypeID
	Return Type
	Params []FuncParam
}

func (fp *FuncProto) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, fp, "args=", len(fp.Params), "return=", fp.Return)
}

func (fp *FuncProto) TypeName() string { return "" }

func (fp *FuncProto) walk(tdq *typeDeque) {
	tdq.push(&fp.Return)
	for i := range fp.Params {
		tdq.push(&fp.Params[i].Type)
	}
}

func (fp *FuncProto) copy() Type {
	cpy := *fp
	cpy.Params = make([]FuncParam, len(fp.Params))
	copy(cpy.Params, fp.Params)
	return &cpy
}

type FuncParam struct {
	Name string
	Type Type
}

// Var is a global variable.
type Var struct {
	TypeID
	Name    string
	Type    Type
	Linkage VarLinkage
}

func (v *Var) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, v, v.Linkage)
}

func (v *Var) TypeName() string { return v.Name }

func (v *Var) walk(tdq *typeDeque) { tdq.push(&v.Type) }
func (v *Var) copy() Type {
	cpy := *v
	return &cpy
}

// Datasec is a global program section containing data.
type Datasec struct {
	TypeID
	Name string
	Size uint32
	Vars []VarSecinfo
}

func (ds *Datasec) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, ds)
}

func (ds *Datasec) TypeName() string { return ds.Name }

func (ds *Datasec) size() uint32 { return ds.Size }

func (ds *Datasec) walk(tdq *typeDeque) {
	for i := range ds.Vars {
		tdq.push(&ds.Vars[i].Type)
	}
}

func (ds *Datasec) copy() Type {
	cpy := *ds
	cpy.Vars = make([]VarSecinfo, len(ds.Vars))
	copy(cpy.Vars, ds.Vars)
	return &cpy
}

// VarSecinfo describes variable in a Datasec.
//
// It is not a valid Type.
type VarSecinfo struct {
	Type   Type
	Offset uint32
	Size   uint32
}

// Float is a float of a given length.
type Float struct {
	TypeID
	Name string

	// The size of the float in bytes.
	Size uint32
}

func (f *Float) Format(fs fmt.State, verb rune) {
	formatType(fs, verb, f, "size=", f.Size*8)
}

func (f *Float) TypeName() string { return f.Name }
func (f *Float) size() uint32     { return f.Size }
func (f *Float) walk(*typeDeque)  {}
func (f *Float) copy() Type {
	cpy := *f
	return &cpy
}

// cycle is a type which had to be elided since it exceeded maxTypeDepth.
type cycle struct {
	root Type
}

func (c *cycle) ID() TypeID                     { return math.MaxUint32 }
func (c *cycle) Format(fs fmt.State, verb rune) { formatType(fs, verb, c, "root=", c.root) }
func (c *cycle) TypeName() string               { return "" }
func (c *cycle) walk(*typeDeque)                {}
func (c *cycle) copy() Type {
	cpy := *c
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

type qualifier interface {
	qualify() Type
}

var (
	_ qualifier = (*Const)(nil)
	_ qualifier = (*Restrict)(nil)
	_ qualifier = (*Volatile)(nil)
)

// Sizeof returns the size of a type in bytes.
//
// Returns an error if the size can't be computed.
func Sizeof(typ Type) (int, error) {
	var (
		n    = int64(1)
		elem int64
	)

	for i := 0; i < maxTypeDepth; i++ {
		switch v := typ.(type) {
		case *Array:
			if n > 0 && int64(v.Nelems) > math.MaxInt64/n {
				return 0, fmt.Errorf("type %s: overflow", typ)
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

		case qualifier:
			typ = v.qualify()
			continue

		default:
			return 0, fmt.Errorf("unsized type %T", typ)
		}

		if n > 0 && elem > math.MaxInt64/n {
			return 0, fmt.Errorf("type %s: overflow", typ)
		}

		size := n * elem
		if int64(int(size)) != size {
			return 0, fmt.Errorf("type %s: overflow", typ)
		}

		return int(size), nil
	}

	return 0, fmt.Errorf("type %s: exceeded type depth", typ)
}

// alignof returns the alignment of a type.
//
// Currently only supports the subset of types necessary for bitfield relocations.
func alignof(typ Type) (int, error) {
	switch t := UnderlyingType(typ).(type) {
	case *Enum:
		return int(t.size()), nil
	case *Int:
		return int(t.Size), nil
	default:
		return 0, fmt.Errorf("can't calculate alignment of %T", t)
	}
}

// copy a Type recursively.
//
// typ may form a cycle. If transform is not nil, it is called with the
// to be copied type, and the return value is copied instead.
func Copy(typ Type, transform func(Type) Type) Type {
	copies := make(copier)
	copies.copy(&typ, transform)
	return typ
}

// copy a slice of Types recursively.
//
// See Copy for the semantics.
func copyTypes(types []Type, transform func(Type) Type) []Type {
	result := make([]Type, len(types))
	copy(result, types)

	copies := make(copier)
	for i := range result {
		copies.copy(&result[i], transform)
	}

	return result
}

type copier map[Type]Type

func (c copier) copy(typ *Type, transform func(Type) Type) {
	var work typeDeque
	for t := typ; t != nil; t = work.pop() {
		// *t is the identity of the type.
		if cpy := c[*t]; cpy != nil {
			*t = cpy
			continue
		}

		var cpy Type
		if transform != nil {
			cpy = transform(*t).copy()
		} else {
			cpy = (*t).copy()
		}

		c[*t] = cpy
		*t = cpy

		// Mark any nested types for copying.
		cpy.walk(&work)
	}
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

// inflateRawTypes takes a list of raw btf types linked via type IDs, and turns
// it into a graph of Types connected via pointers.
//
// Returns a map of named types (so, where NameOff is non-zero) and a slice of types
// indexed by TypeID. Since BTF ignores compilation units, multiple types may share
// the same name. A Type may form a cyclic graph by pointing at itself.
func inflateRawTypes(rawTypes []rawType, rawStrings *stringTable) ([]Type, map[essentialName][]Type, error) {
	types := make([]Type, 0, len(rawTypes)+1)
	types = append(types, (*Void)(nil))
	namedTypes := make(map[essentialName][]Type)
	type fixupDef struct {
		id  TypeID
		typ *Type
	}

	var fixups []fixupDef
	fixup := func(id TypeID, typ *Type) {
		if id < TypeID(len(types)) {
			// We've already inflated this type, fix it up immediately.
			*typ = types[id]
			return
		}
		fixups = append(fixups, fixupDef{id, typ})
	}

	type assertion struct {
		typ  *Type
		want reflect.Type
	}

	var assertions []assertion
	assert := func(typ *Type, want reflect.Type) error {
		if *typ != nil {
			// The type has already been fixed up, check the type immediately.
			if reflect.TypeOf(*typ) != want {
				return fmt.Errorf("expected %s, got %T", want, *typ)
			}
			return nil
		}
		assertions = append(assertions, assertion{typ, want})
		return nil
	}

	convertMembers := func(raw []btfMember, kindFlag bool) ([]Member, error) {
		// NB: The fixup below relies on pre-allocating this array to
		// work, since otherwise append might re-allocate members.
		members := make([]Member, 0, len(raw))
		for i, btfMember := range raw {
			name, err := rawStrings.Lookup(btfMember.NameOff)
			if err != nil {
				return nil, fmt.Errorf("can't get name for member %d: %w", i, err)
			}
			m := Member{
				Name:       name,
				OffsetBits: btfMember.Offset,
			}
			if kindFlag {
				m.BitfieldSize = btfMember.Offset >> 24
				m.OffsetBits &= 0xffffff
			}
			members = append(members, m)
		}
		for i := range members {
			fixup(raw[i].Type, &members[i].Type)
		}
		return members, nil
	}

	for i, raw := range rawTypes {
		var (
			// Void is defined to always be type ID 0, and is thus
			// omitted from BTF.
			id  = TypeID(i + 1)
			typ Type
		)

		name, err := rawStrings.Lookup(raw.NameOff)
		if err != nil {
			return nil, nil, fmt.Errorf("get name for type id %d: %w", id, err)
		}

		switch raw.Kind() {
		case kindInt:
			encoding, offset, bits := intEncoding(*raw.data.(*uint32))
			typ = &Int{id, name, raw.Size(), encoding, offset, bits}

		case kindPointer:
			ptr := &Pointer{id, nil}
			fixup(raw.Type(), &ptr.Target)
			typ = ptr

		case kindArray:
			btfArr := raw.data.(*btfArray)

			// IndexType is unused according to btf.rst.
			// Don't make it available right now.
			arr := &Array{id, nil, btfArr.Nelems}
			fixup(btfArr.Type, &arr.Type)
			typ = arr

		case kindStruct:
			members, err := convertMembers(raw.data.([]btfMember), raw.KindFlag())
			if err != nil {
				return nil, nil, fmt.Errorf("struct %s (id %d): %w", name, id, err)
			}
			typ = &Struct{id, name, raw.Size(), members}

		case kindUnion:
			members, err := convertMembers(raw.data.([]btfMember), raw.KindFlag())
			if err != nil {
				return nil, nil, fmt.Errorf("union %s (id %d): %w", name, id, err)
			}
			typ = &Union{id, name, raw.Size(), members}

		case kindEnum:
			rawvals := raw.data.([]btfEnum)
			vals := make([]EnumValue, 0, len(rawvals))
			for i, btfVal := range rawvals {
				name, err := rawStrings.Lookup(btfVal.NameOff)
				if err != nil {
					return nil, nil, fmt.Errorf("get name for enum value %d: %s", i, err)
				}
				vals = append(vals, EnumValue{
					Name:  name,
					Value: btfVal.Val,
				})
			}
			typ = &Enum{id, name, vals}

		case kindForward:
			if raw.KindFlag() {
				typ = &Fwd{id, name, FwdUnion}
			} else {
				typ = &Fwd{id, name, FwdStruct}
			}

		case kindTypedef:
			typedef := &Typedef{id, name, nil}
			fixup(raw.Type(), &typedef.Type)
			typ = typedef

		case kindVolatile:
			volatile := &Volatile{id, nil}
			fixup(raw.Type(), &volatile.Type)
			typ = volatile

		case kindConst:
			cnst := &Const{id, nil}
			fixup(raw.Type(), &cnst.Type)
			typ = cnst

		case kindRestrict:
			restrict := &Restrict{id, nil}
			fixup(raw.Type(), &restrict.Type)
			typ = restrict

		case kindFunc:
			fn := &Func{id, name, nil, raw.Linkage()}
			fixup(raw.Type(), &fn.Type)
			if err := assert(&fn.Type, reflect.TypeOf((*FuncProto)(nil))); err != nil {
				return nil, nil, err
			}
			typ = fn

		case kindFuncProto:
			rawparams := raw.data.([]btfParam)
			params := make([]FuncParam, 0, len(rawparams))
			for i, param := range rawparams {
				name, err := rawStrings.Lookup(param.NameOff)
				if err != nil {
					return nil, nil, fmt.Errorf("get name for func proto parameter %d: %s", i, err)
				}
				params = append(params, FuncParam{
					Name: name,
				})
			}
			for i := range params {
				fixup(rawparams[i].Type, &params[i].Type)
			}

			fp := &FuncProto{id, nil, params}
			fixup(raw.Type(), &fp.Return)
			typ = fp

		case kindVar:
			variable := raw.data.(*btfVariable)
			v := &Var{id, name, nil, VarLinkage(variable.Linkage)}
			fixup(raw.Type(), &v.Type)
			typ = v

		case kindDatasec:
			btfVars := raw.data.([]btfVarSecinfo)
			vars := make([]VarSecinfo, 0, len(btfVars))
			for _, btfVar := range btfVars {
				vars = append(vars, VarSecinfo{
					Offset: btfVar.Offset,
					Size:   btfVar.Size,
				})
			}
			for i := range vars {
				fixup(btfVars[i].Type, &vars[i].Type)
				if err := assert(&vars[i].Type, reflect.TypeOf((*Var)(nil))); err != nil {
					return nil, nil, err
				}
			}
			typ = &Datasec{id, name, raw.SizeType, vars}

		case kindFloat:
			typ = &Float{id, name, raw.Size()}

		default:
			return nil, nil, fmt.Errorf("type id %d: unknown kind: %v", id, raw.Kind())
		}

		types = append(types, typ)

		if name := newEssentialName(typ.TypeName()); name != "" {
			namedTypes[name] = append(namedTypes[name], typ)
		}
	}

	for _, fixup := range fixups {
		i := int(fixup.id)
		if i >= len(types) {
			return nil, nil, fmt.Errorf("reference to invalid type id: %d", fixup.id)
		}

		*fixup.typ = types[i]
	}

	for _, assertion := range assertions {
		if reflect.TypeOf(*assertion.typ) != assertion.want {
			return nil, nil, fmt.Errorf("expected %s, got %T", assertion.want, *assertion.typ)
		}
	}

	return types, namedTypes, nil
}

// essentialName represents the name of a BTF type stripped of any flavor
// suffixes after a ___ delimiter.
type essentialName string

// newEssentialName returns name without a ___ suffix.
//
// CO-RE has the concept of 'struct flavors', which are used to deal with
// changes in kernel data structures. Anything after three underscores
// in a type name is ignored for the purpose of finding a candidate type
// in the kernel's BTF.
func newEssentialName(name string) essentialName {
	lastIdx := strings.LastIndex(name, "___")
	if lastIdx > 0 {
		return essentialName(name[:lastIdx])
	}
	return essentialName(name)
}

// UnderlyingType skips qualifiers and Typedefs.
func UnderlyingType(typ Type) Type {
	result := typ
	for depth := 0; depth <= maxTypeDepth; depth++ {
		switch v := (result).(type) {
		case qualifier:
			result = v.qualify()
		case *Typedef:
			result = v.Type
		default:
			return result
		}
	}
	return &cycle{typ}
}

type formatState struct {
	fmt.State
	depth int
}

// formattableType is a subset of Type, to ease unit testing of formatType.
type formattableType interface {
	fmt.Formatter
	TypeName() string
}

// formatType formats a type in a canonical form.
//
// Handles cyclical types by only printing cycles up to a certain depth. Elements
// in extra are separated by spaces unless the preceding element is a string
// ending in '='.
func formatType(f fmt.State, verb rune, t formattableType, extra ...interface{}) {
	if verb != 'v' && verb != 's' {
		fmt.Fprintf(f, "{UNRECOGNIZED: %c}", verb)
		return
	}

	// This is the same as %T, but elides the package name. Assumes that
	// formattableType is implemented by a pointer receiver.
	goTypeName := reflect.TypeOf(t).Elem().Name()
	_, _ = io.WriteString(f, goTypeName)

	if name := t.TypeName(); name != "" {
		// Output BTF type name if present.
		fmt.Fprintf(f, ":%q", name)
	}

	if f.Flag('+') {
		// Output address if requested.
		fmt.Fprintf(f, ":%#p", t)
	}

	if verb == 's' {
		// %s omits details.
		return
	}

	var depth int
	if ps, ok := f.(*formatState); ok {
		depth = ps.depth
		f = ps.State
	}

	maxDepth, ok := f.Width()
	if !ok {
		maxDepth = 0
	}

	if depth > maxDepth {
		// We've reached the maximum depth. This avoids infinite recursion even
		// for cyclical types.
		return
	}

	if len(extra) == 0 {
		return
	}

	wantSpace := false
	_, _ = io.WriteString(f, "[")
	for _, arg := range extra {
		if wantSpace {
			_, _ = io.WriteString(f, " ")
		}

		switch v := arg.(type) {
		case string:
			_, _ = io.WriteString(f, v)
			wantSpace = len(v) > 0 && v[len(v)-1] != '='
			continue

		case formattableType:
			v.Format(&formatState{f, depth + 1}, verb)

		default:
			fmt.Fprint(f, arg)
		}

		wantSpace = true
	}
	_, _ = io.WriteString(f, "]")
}
