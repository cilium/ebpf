package btf

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"iter"
	"maps"
	"math"
	"os"
	"reflect"
	"sync"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/sys"
)

const btfMagic = 0xeB9F

// Errors returned by BTF functions.
var (
	ErrNotSupported    = internal.ErrNotSupported
	ErrNotFound        = errors.New("not found")
	ErrNoExtendedInfo  = errors.New("no extended info")
	ErrMultipleMatches = errors.New("multiple matching types")
)

// ID represents the unique ID of a BTF object.
type ID = sys.BTFID

// immutableTypes is a set of types which musn't be changed.
type immutableTypes struct {
	// All types contained by the spec, not including types from the base in
	// case the spec was parsed from split BTF.
	types []Type

	// Type IDs indexed by type.
	typeIDs map[Type]TypeID

	// The ID of the first type in types.
	firstTypeID TypeID

	// Types indexed by essential name.
	// Includes all struct flavors and types with the same name.
	namedTypes map[essentialName][]TypeID

	// Byte order of the types. This affects things like struct member order
	// when using bitfields.
	byteOrder binary.ByteOrder
}

func (s *immutableTypes) typeByID(id TypeID) (Type, bool) {
	if id < s.firstTypeID {
		return nil, false
	}

	index := int(id - s.firstTypeID)
	if index >= len(s.types) {
		return nil, false
	}

	return s.types[index], true
}

// mutableTypes is a set of types which may be changed.
type mutableTypes struct {
	imm           immutableTypes
	mu            sync.RWMutex    // protects copies below
	copies        map[Type]Type   // map[orig]copy
	copiedTypeIDs map[Type]TypeID // map[copy]origID
}

// add a type to the set of mutable types.
//
// Copies type and all of its children once. Repeated calls with the same type
// do not copy again.
func (mt *mutableTypes) add(typ Type, typeIDs map[Type]TypeID) Type {
	mt.mu.RLock()
	cpy, ok := mt.copies[typ]
	mt.mu.RUnlock()

	if ok {
		// Fast path: the type has been copied before.
		return cpy
	}

	// modifyGraphPreorder copies the type graph node by node, so we can't drop
	// the lock in between.
	mt.mu.Lock()
	defer mt.mu.Unlock()

	return copyType(typ, typeIDs, mt.copies, mt.copiedTypeIDs)
}

// copy a set of mutable types.
func (mt *mutableTypes) copy() *mutableTypes {
	if mt == nil {
		return nil
	}

	// Prevent concurrent modification of mt.copiedTypeIDs.
	mt.mu.RLock()
	defer mt.mu.RUnlock()

	mtCopy := &mutableTypes{
		mt.imm,
		sync.RWMutex{},
		make(map[Type]Type, len(mt.copies)),
		make(map[Type]TypeID, len(mt.copiedTypeIDs)),
	}

	copiesOfCopies := make(map[Type]Type, len(mt.copies))
	for orig, copy := range mt.copies {
		// NB: We make a copy of copy, not orig, so that changes to mutable types
		// are preserved.
		copyOfCopy := copyType(copy, mt.copiedTypeIDs, copiesOfCopies, mtCopy.copiedTypeIDs)
		mtCopy.copies[orig] = copyOfCopy
	}

	return mtCopy
}

func (mt *mutableTypes) typeID(typ Type) (TypeID, error) {
	if _, ok := typ.(*Void); ok {
		// Equality is weird for void, since it is a zero sized type.
		return 0, nil
	}

	mt.mu.RLock()
	defer mt.mu.RUnlock()

	id, ok := mt.copiedTypeIDs[typ]
	if !ok {
		return 0, fmt.Errorf("no ID for type %s: %w", typ, ErrNotFound)
	}

	return id, nil
}

func (mt *mutableTypes) typeByID(id TypeID) (Type, bool) {
	immT, ok := mt.imm.typeByID(id)
	if !ok {
		return nil, false
	}

	return mt.add(immT, mt.imm.typeIDs), true
}

func (mt *mutableTypes) typeIDsByName(name essentialName) []TypeID {
	return mt.imm.namedTypes[name]
}

type elfData struct {
	sectionSizes  map[string]uint32
	symbolOffsets map[elfSymbol]uint32
	fixups        map[Type]bool
}

type elfSymbol struct {
	section string
	name    string
}

// Spec allows querying a set of Types and loading the set into the
// kernel.
type Spec struct {
	*mutableTypes

	// String table from ELF.
	strings *stringTable

	// Additional data from ELF, may be nil.
	elf *elfData
}

// LoadSpec opens file and calls LoadSpecFromReader on it.
func LoadSpec(file string) (*Spec, error) {
	fh, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fh.Close()

	return LoadSpecFromReader(fh)
}

// LoadSpecFromReader reads from an ELF or a raw BTF blob.
//
// Returns ErrNotFound if reading from an ELF which contains no BTF. ExtInfos
// may be nil.
func LoadSpecFromReader(rd io.ReaderAt) (*Spec, error) {
	file, err := internal.NewSafeELFFile(rd)
	if err != nil {
		if bo := guessRawBTFByteOrder(rd); bo != nil {
			return loadRawSpec(io.NewSectionReader(rd, 0, math.MaxInt64), bo, nil)
		}

		return nil, err
	}

	return loadSpecFromELF(file)
}

// LoadSpecAndExtInfosFromReader reads from an ELF.
//
// ExtInfos may be nil if the ELF doesn't contain section metadata.
// Returns ErrNotFound if the ELF contains no BTF.
func LoadSpecAndExtInfosFromReader(rd io.ReaderAt) (*Spec, *ExtInfos, error) {
	file, err := internal.NewSafeELFFile(rd)
	if err != nil {
		return nil, nil, err
	}

	spec, err := loadSpecFromELF(file)
	if err != nil {
		return nil, nil, err
	}

	extInfos, err := loadExtInfosFromELF(file, spec)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, nil, err
	}

	return spec, extInfos, nil
}

// symbolOffsets extracts all symbols offsets from an ELF and indexes them by
// section and variable name.
//
// References to variables in BTF data sections carry unsigned 32-bit offsets.
// Some ELF symbols (e.g. in vmlinux) may point to virtual memory that is well
// beyond this range. Since these symbols cannot be described by BTF info,
// ignore them here.
func symbolOffsets(file *internal.SafeELFFile) (map[elfSymbol]uint32, error) {
	symbols, err := file.Symbols()
	if err != nil {
		return nil, fmt.Errorf("can't read symbols: %v", err)
	}

	offsets := make(map[elfSymbol]uint32)
	for _, sym := range symbols {
		if idx := sym.Section; idx >= elf.SHN_LORESERVE && idx <= elf.SHN_HIRESERVE {
			// Ignore things like SHN_ABS
			continue
		}

		if sym.Value > math.MaxUint32 {
			// VarSecinfo offset is u32, cannot reference symbols in higher regions.
			continue
		}

		if int(sym.Section) >= len(file.Sections) {
			return nil, fmt.Errorf("symbol %s: invalid section %d", sym.Name, sym.Section)
		}

		secName := file.Sections[sym.Section].Name
		offsets[elfSymbol{secName, sym.Name}] = uint32(sym.Value)
	}

	return offsets, nil
}

func loadSpecFromELF(file *internal.SafeELFFile) (*Spec, error) {
	var (
		btfSection   *elf.Section
		sectionSizes = make(map[string]uint32)
	)

	for _, sec := range file.Sections {
		switch sec.Name {
		case ".BTF":
			btfSection = sec
		default:
			if sec.Type != elf.SHT_PROGBITS && sec.Type != elf.SHT_NOBITS {
				break
			}

			if sec.Size > math.MaxUint32 {
				return nil, fmt.Errorf("section %s exceeds maximum size", sec.Name)
			}

			sectionSizes[sec.Name] = uint32(sec.Size)
		}
	}

	if btfSection == nil {
		return nil, fmt.Errorf("btf: %w", ErrNotFound)
	}

	offsets, err := symbolOffsets(file)
	if err != nil {
		return nil, err
	}

	if btfSection.ReaderAt == nil {
		return nil, fmt.Errorf("compressed BTF is not supported")
	}

	spec, err := loadRawSpec(btfSection.ReaderAt, file.ByteOrder, nil)
	if err != nil {
		return nil, err
	}

	spec.elf = &elfData{
		sectionSizes,
		offsets,
		make(map[Type]bool),
	}

	return spec, nil
}

func loadRawSpec(btf io.ReaderAt, bo binary.ByteOrder, base *Spec) (*Spec, error) {
	var (
		baseStrings *stringTable
		firstTypeID TypeID
		err         error
	)

	if base != nil {
		if base.imm.firstTypeID != 0 {
			return nil, fmt.Errorf("can't use split BTF as base")
		}

		baseStrings = base.strings

		firstTypeID, err = base.nextTypeID()
		if err != nil {
			return nil, err
		}
	}

	buf := internal.NewBufferedSectionReader(btf, 0, math.MaxInt64)
	header, err := parseBTFHeader(buf, bo)
	if err != nil {
		return nil, fmt.Errorf("parsing .BTF header: %v", err)
	}

	rawStrings, err := readStringTable(io.NewSectionReader(btf, header.stringStart(), int64(header.StringLen)),
		baseStrings)
	if err != nil {
		return nil, fmt.Errorf("can't read type names: %w", err)
	}

	buf.Reset(io.NewSectionReader(btf, header.typeStart(), int64(header.TypeLen)))
	types, err := readAndInflateTypes(buf, bo, header.TypeLen, rawStrings, base)
	if err != nil {
		return nil, err
	}

	typeIDs, typesByName := indexTypes(types, firstTypeID)

	return &Spec{
		&mutableTypes{
			immutableTypes{
				types,
				typeIDs,
				firstTypeID,
				typesByName,
				bo,
			},
			sync.RWMutex{},
			make(map[Type]Type),
			make(map[Type]TypeID),
		},
		rawStrings,
		nil,
	}, nil
}

func indexTypes(types []Type, firstTypeID TypeID) (map[Type]TypeID, map[essentialName][]TypeID) {
	namedTypes := 0
	for _, typ := range types {
		if typ.TypeName() != "" {
			// Do a pre-pass to figure out how big types by name has to be.
			// Most types have unique names, so it's OK to ignore essentialName
			// here.
			namedTypes++
		}
	}

	typeIDs := make(map[Type]TypeID, len(types))
	typesByName := make(map[essentialName][]TypeID, namedTypes)

	for i, typ := range types {
		id := firstTypeID + TypeID(i)
		typeIDs[typ] = id

		if name := newEssentialName(typ.TypeName()); name != "" {
			typesByName[name] = append(typesByName[name], id)
		}
	}

	return typeIDs, typesByName
}

func guessRawBTFByteOrder(r io.ReaderAt) binary.ByteOrder {
	buf := new(bufio.Reader)
	for _, bo := range []binary.ByteOrder{
		binary.LittleEndian,
		binary.BigEndian,
	} {
		buf.Reset(io.NewSectionReader(r, 0, math.MaxInt64))
		if _, err := parseBTFHeader(buf, bo); err == nil {
			return bo
		}
	}

	return nil
}

// fixupDatasec attempts to patch up missing info in Datasecs and its members by
// supplementing them with information from the ELF headers and symbol table.
func (elf *elfData) fixupDatasec(typ Type) error {
	if ds, ok := typ.(*Datasec); ok {
		if elf.fixups[ds] {
			return nil
		}
		elf.fixups[ds] = true

		name := ds.Name

		// Some Datasecs are virtual and don't have corresponding ELF sections.
		switch name {
		case ".ksyms":
			// .ksyms describes forward declarations of kfunc signatures, as well as
			// references to kernel symbols.
			// Nothing to fix up, all sizes and offsets are 0.
			for _, vsi := range ds.Vars {
				switch t := vsi.Type.(type) {
				case *Func:
					continue
				case *Var:
					if _, ok := t.Type.(*Void); !ok {
						return fmt.Errorf("data section %s: expected %s to be *Void, not %T: %w", name, vsi.Type.TypeName(), vsi.Type, ErrNotSupported)
					}
				default:
					return fmt.Errorf("data section %s: expected to be either *btf.Func or *btf.Var, not %T: %w", name, vsi.Type, ErrNotSupported)
				}
			}

			return nil
		case ".kconfig":
			// .kconfig has a size of 0 and has all members' offsets set to 0.
			// Fix up all offsets and set the Datasec's size.
			if err := fixupDatasecLayout(ds); err != nil {
				return err
			}

			// Fix up extern to global linkage to avoid a BTF verifier error.
			for _, vsi := range ds.Vars {
				vsi.Type.(*Var).Linkage = GlobalVar
			}

			return nil
		}

		if ds.Size != 0 {
			return nil
		}

		ds.Size, ok = elf.sectionSizes[name]
		if !ok {
			return fmt.Errorf("data section %s: missing size", name)
		}

		for i := range ds.Vars {
			symName := ds.Vars[i].Type.TypeName()
			ds.Vars[i].Offset, ok = elf.symbolOffsets[elfSymbol{name, symName}]
			if !ok {
				return fmt.Errorf("data section %s: missing offset for symbol %s", name, symName)
			}
		}
	}

	return nil
}

// fixupDatasecLayout populates ds.Vars[].Offset according to var sizes and
// alignment. Calculate and set ds.Size.
func fixupDatasecLayout(ds *Datasec) error {
	var off uint32

	for i, vsi := range ds.Vars {
		v, ok := vsi.Type.(*Var)
		if !ok {
			return fmt.Errorf("member %d: unsupported type %T", i, vsi.Type)
		}

		size, err := Sizeof(v.Type)
		if err != nil {
			return fmt.Errorf("variable %s: getting size: %w", v.Name, err)
		}
		align, err := alignof(v.Type)
		if err != nil {
			return fmt.Errorf("variable %s: getting alignment: %w", v.Name, err)
		}

		// Align the current member based on the offset of the end of the previous
		// member and the alignment of the current member.
		off = internal.Align(off, uint32(align))

		ds.Vars[i].Offset = off

		off += uint32(size)
	}

	ds.Size = off

	return nil
}

// Copy creates a copy of Spec.
func (s *Spec) Copy() *Spec {
	if s == nil {
		return nil
	}

	cpy := &Spec{
		s.copy(),
		s.strings,
		nil,
	}

	if s.elf != nil {
		cpy.elf = &elfData{
			s.elf.sectionSizes,
			s.elf.symbolOffsets,
			maps.Clone(s.elf.fixups),
		}
	}

	return cpy
}

// nextTypeID returns the next unallocated type ID or an error if there are no
// more type IDs.
func (s *Spec) nextTypeID() (TypeID, error) {
	id := s.imm.firstTypeID + TypeID(len(s.imm.types))
	if id < s.imm.firstTypeID {
		return 0, fmt.Errorf("no more type IDs")
	}
	return id, nil
}

// TypeByID returns the BTF Type with the given type ID.
//
// Returns an error wrapping ErrNotFound if a Type with the given ID
// does not exist in the Spec.
func (s *Spec) TypeByID(id TypeID) (Type, error) {
	typ, ok := s.typeByID(id)
	if !ok {
		return nil, fmt.Errorf("look up type with ID %d (first ID is %d): %w", id, s.imm.firstTypeID, ErrNotFound)
	}

	if s.elf == nil {
		return typ, nil
	}

	if err := s.elf.fixupDatasec(typ); err != nil {
		return nil, err
	}

	return typ, nil
}

// TypeID returns the ID for a given Type.
//
// Returns an error wrapping [ErrNotFound] if the type isn't part of the Spec.
func (s *Spec) TypeID(typ Type) (TypeID, error) {
	return s.typeID(typ)
}

// AnyTypesByName returns a list of BTF Types with the given name.
//
// If the BTF blob describes multiple compilation units like vmlinux, multiple
// Types with the same name and kind can exist, but might not describe the same
// data structure.
//
// Returns an error wrapping ErrNotFound if no matching Type exists in the Spec.
func (s *Spec) AnyTypesByName(name string) ([]Type, error) {
	typeIDs := s.typeIDsByName(newEssentialName(name))
	if len(typeIDs) == 0 {
		return nil, fmt.Errorf("type name %s: %w", name, ErrNotFound)
	}

	// Return a copy to prevent changes to namedTypes.
	result := make([]Type, 0, len(typeIDs))
	for _, id := range typeIDs {
		typ, err := s.TypeByID(id)
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("no type with ID %d", id)
		} else if err != nil {
			return nil, err
		}

		// Match against the full name, not just the essential one
		// in case the type being looked up is a struct flavor.
		if typ.TypeName() == name {
			result = append(result, typ)
		}
	}
	return result, nil
}

// AnyTypeByName returns a Type with the given name.
//
// Returns an error if multiple types of that name exist.
func (s *Spec) AnyTypeByName(name string) (Type, error) {
	types, err := s.AnyTypesByName(name)
	if err != nil {
		return nil, err
	}

	if len(types) > 1 {
		return nil, fmt.Errorf("found multiple types: %v", types)
	}

	return types[0], nil
}

// TypeByName searches for a Type with a specific name. Since multiple Types
// with the same name can exist, the parameter typ is taken to narrow down the
// search in case of a clash.
//
// typ must be a non-nil pointer to an implementation of a Type. On success, the
// address of the found Type will be copied to typ.
//
// Returns an error wrapping ErrNotFound if no matching Type exists in the Spec.
// Returns an error wrapping ErrMultipleTypes if multiple candidates are found.
func (s *Spec) TypeByName(name string, typ interface{}) error {
	typeInterface := reflect.TypeOf((*Type)(nil)).Elem()

	// typ may be **T or *Type
	typValue := reflect.ValueOf(typ)
	if typValue.Kind() != reflect.Ptr {
		return fmt.Errorf("%T is not a pointer", typ)
	}

	typPtr := typValue.Elem()
	if !typPtr.CanSet() {
		return fmt.Errorf("%T cannot be set", typ)
	}

	wanted := typPtr.Type()
	if wanted == typeInterface {
		// This is *Type. Unwrap the value's type.
		wanted = typPtr.Elem().Type()
	}

	if !wanted.AssignableTo(typeInterface) {
		return fmt.Errorf("%T does not satisfy Type interface", typ)
	}

	types, err := s.AnyTypesByName(name)
	if err != nil {
		return err
	}

	var candidate Type
	for _, typ := range types {
		if reflect.TypeOf(typ) != wanted {
			continue
		}

		if candidate != nil {
			return fmt.Errorf("type %s(%T): %w", name, typ, ErrMultipleMatches)
		}

		candidate = typ
	}

	if candidate == nil {
		return fmt.Errorf("%s %s: %w", wanted, name, ErrNotFound)
	}

	typPtr.Set(reflect.ValueOf(candidate))

	return nil
}

// LoadSplitSpecFromReader loads split BTF from a reader.
//
// Types from base are used to resolve references in the split BTF.
// The returned Spec only contains types from the split BTF, not from the base.
func LoadSplitSpecFromReader(r io.ReaderAt, base *Spec) (*Spec, error) {
	return loadRawSpec(r, internal.NativeEndian, base)
}

// All iterates over all types.
func (s *Spec) All() iter.Seq2[Type, error] {
	return func(yield func(Type, error) bool) {
		for id := s.imm.firstTypeID; ; id++ {
			typ, err := s.TypeByID(id)
			if errors.Is(err, ErrNotFound) {
				return
			} else if err != nil {
				yield(nil, err)
				return
			}

			// Skip declTags, during unmarshaling declTags become `Tags` fields of other types.
			// We keep them in the spec to avoid holes in the ID space, but for the purposes of
			// iteration, they are not useful to the user.
			if _, ok := typ.(*declTag); ok {
				continue
			}

			if !yield(typ, nil) {
				return
			}
		}
	}
}
