package ebpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"strings"

	"github.com/newtools/ebpf/asm"

	"github.com/pkg/errors"
)

type elfCode struct {
	*elf.File
	symtab *symtab
}

// LoadCollectionSpecFromReader parses an io.ReaderAt that represents an ELF layout
// into a CollectionSpec.
func LoadCollectionSpecFromReader(code io.ReaderAt) (*CollectionSpec, error) {
	f, err := elf.NewFile(code)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	symbols, err := f.Symbols()
	if err != nil {
		return nil, errors.Wrap(err, "load symbols")
	}

	ec := &elfCode{f, newSymtab(symbols)}

	var licenseSection, versionSection *elf.Section
	progSections := make(map[int]*elf.Section)
	relSections := make(map[int]*elf.Section)
	mapSections := make(map[int]*elf.Section)
	for i, sec := range ec.Sections {
		switch {
		case strings.HasPrefix(sec.Name, "license"):
			licenseSection = sec
		case strings.HasPrefix(sec.Name, "version"):
			versionSection = sec
		case strings.HasPrefix(sec.Name, "maps"):
			mapSections[i] = sec
		case sec.Type == elf.SHT_REL:
			if int(sec.Info) >= len(ec.Sections) {
				return nil, errors.Errorf("found relocation section %v for missing section %v", i, sec.Info)
			}

			// Store relocations under the section index of the target
			idx := int(sec.Info)
			if relSections[idx] != nil {
				return nil, errors.Errorf("section %d has multiple relocation sections", idx)
			}
			relSections[idx] = sec
		case sec.Type == elf.SHT_PROGBITS && (sec.Flags&elf.SHF_EXECINSTR) != 0 && sec.Size > 0:
			progSections[i] = sec
		}
	}

	license, err := loadLicense(licenseSection)
	if err != nil {
		return nil, errors.Wrap(err, "load license")
	}

	version, err := loadVersion(versionSection, ec.ByteOrder)
	if err != nil {
		return nil, errors.Wrap(err, "load version")
	}

	maps, err := ec.loadMaps(mapSections)
	if err != nil {
		return nil, errors.Wrap(err, "load maps")
	}

	progs, libs, err := ec.loadPrograms(progSections, relSections, license, version)
	if err != nil {
		return nil, errors.Wrap(err, "load programs")
	}

	if len(libs) > 0 {
		for name, prog := range progs {
			editor := Edit(&prog.Instructions)
			if err := editor.Link(libs...); err != nil {
				return nil, errors.Wrapf(err, "program %s", name)
			}
		}
	}

	return &CollectionSpec{maps, progs}, nil
}

func loadLicense(sec *elf.Section) (string, error) {
	if sec == nil {
		return "", errors.Errorf("missing license section")
	}
	data, err := sec.Data()
	if err != nil {
		return "", errors.Wrapf(err, "section %s", sec.Name)
	}
	return string(bytes.TrimRight(data, "\000")), nil
}

func loadVersion(sec *elf.Section, bo binary.ByteOrder) (uint32, error) {
	if sec == nil {
		return 0, nil
	}
	data, err := sec.Data()
	if err != nil {
		return 0, errors.Wrapf(err, "section %s", sec.Name)
	}
	var version uint32
	return version, binary.Read(bytes.NewReader(data), bo, &version)
}

func (ec *elfCode) loadPrograms(progSections, relSections map[int]*elf.Section, license string, version uint32) (map[string]*ProgramSpec, []asm.Instructions, error) {
	progs := make(map[string]*ProgramSpec)
	var libs []asm.Instructions
	for idx, prog := range progSections {
		data, err := prog.Data()
		if err != nil {
			return nil, nil, err
		}

		funcSym := ec.symtab.forSectionOffset(idx, 0)
		if funcSym == nil {
			return nil, nil, errors.Errorf("section %v: no label at start", prog.Name)
		}

		var insns asm.Instructions
		offsets, err := insns.Unmarshal(bytes.NewReader(data), ec.ByteOrder)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "program %s", funcSym.Name)
		}

		err = assignSymbols(ec.symtab.forSection(idx), offsets, insns)
		if err != nil {
			return nil, nil, errors.Wrapf(err, "program %s", funcSym.Name)
		}

		if rels := relSections[idx]; rels != nil {
			err = ec.applyRelocations(insns, rels, offsets)
			if err != nil {
				return nil, nil, errors.Wrapf(err, "program %s", funcSym.Name)
			}
		}

		if progType := getProgType(prog.Name); progType == Unrecognized {
			// There is no single name we can use for "library" sections,
			// since they may contain multiple functions. We'll decode the
			// labels they contain later on, and then link sections that way.
			libs = append(libs, insns)
		} else {
			progs[funcSym.Name] = &ProgramSpec{
				Type:          progType,
				License:       license,
				KernelVersion: version,
				Instructions:  insns,
			}
		}
	}
	return progs, libs, nil
}

func (ec *elfCode) loadMaps(mapSections map[int]*elf.Section) (map[string]*MapSpec, error) {
	maps := make(map[string]*MapSpec)
	for idx, sec := range mapSections {
		// TODO: Iterate symbols
		n := len(ec.symtab.forSection(idx))
		if n == 0 {
			return nil, errors.Errorf("section %v: no symbols", sec.Name)
		}

		data, err := sec.Data()
		if err != nil {
			return nil, err
		}

		if len(data)%n != 0 {
			return nil, errors.Errorf("map descriptors are not of equal size")
		}

		size := len(data) / n
		var ordered []*MapSpec
		for i := 0; i < n; i++ {
			rd := bytes.NewReader(data[i*size : i*size+size])
			mapSym := ec.symtab.forSectionOffset(idx, uint64(i*size))
			if mapSym == nil {
				return nil, errors.Errorf("section %s: missing symbol for map #%d", sec.Name, i)
			}

			name := mapSym.Name
			if maps[name] != nil {
				return nil, errors.Errorf("section %v: map %v already exists", sec.Name, name)
			}

			var spec MapSpec
			var inner uint32
			switch {
			case binary.Read(rd, ec.ByteOrder, &spec.Type) != nil:
				return nil, errors.Errorf("map %v: missing type", name)
			case binary.Read(rd, ec.ByteOrder, &spec.KeySize) != nil:
				return nil, errors.Errorf("map %v: missing key size", name)
			case binary.Read(rd, ec.ByteOrder, &spec.ValueSize) != nil:
				return nil, errors.Errorf("map %v: missing value size", name)
			case binary.Read(rd, ec.ByteOrder, &spec.MaxEntries) != nil:
				return nil, errors.Errorf("map %v: missing max entries", name)
			case binary.Read(rd, ec.ByteOrder, &spec.Flags) != nil:
				return nil, errors.Errorf("map %v: missing flags", name)
			case rd.Len() > 0 && binary.Read(rd, ec.ByteOrder, &inner) != nil:
				return nil, errors.Errorf("map %v: can't read inner map index", name)
			}

			if rd.Len() != 0 {
				return nil, errors.Errorf("map %v: unknown fields in definition", name)
			}

			if spec.Type == ArrayOfMaps || spec.Type == HashOfMaps {
				if int(inner) > len(ordered) {
					return nil, errors.Errorf("map %v: invalid inner map index %d", name, inner)
				}

				innerSpec := ordered[int(inner)]
				if innerSpec.InnerMap != nil {
					return nil, errors.Errorf("map %v: can't nest map of map", name)
				}
				spec.InnerMap = innerSpec
			}

			maps[name] = &spec
			ordered = append(ordered, &spec)
		}
	}
	return maps, nil
}

func getProgType(v string) ProgType {
	types := map[string]ProgType{
		// From https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/samples/bpf/bpf_load.c?id=fb40c9ddd66b9c9bb811bbee125b3cb3ba1faee7#n60
		"socket":      SocketFilter,
		"seccomp":     SocketFilter,
		"kprobe/":     Kprobe,
		"kretprobe/":  Kprobe,
		"tracepoint/": TracePoint,
		"xdp":         XDP,
		"perf_event":  PerfEvent,
		"cgroup/skb":  CGroupSKB,
		"cgroup/sock": CGroupSock,
		// From https://github.com/CumulusNetworks/iproute2/blob/6335c5ff67202cf5b39eb929e2a0a5bb133627ba/include/bpf_elf.h#L19
		"classifier": SchedCLS,
		"action":     SchedACT,
	}
	for k, t := range types {
		if strings.HasPrefix(v, k) {
			return t
		}
	}
	return Unrecognized
}

func assignSymbols(symbolOffsets map[uint64]*elf.Symbol, insOffsets map[uint64]int, insns asm.Instructions) error {
	for offset, sym := range symbolOffsets {
		i, ok := insOffsets[offset]
		if !ok {
			return errors.Errorf("symbol %s: no instruction at offset %d", sym.Name, offset)
		}
		insns[i].Symbol = sym.Name
	}
	return nil
}

func (ec *elfCode) applyRelocations(insns asm.Instructions, sec *elf.Section, offsets map[uint64]int) error {
	if sec.Entsize < 16 {
		return errors.Errorf("section %v: rls are less than 16 bytes", sec.Name)
	}

	data, err := sec.Data()
	if err != nil {
		return err
	}

	nRels := int(sec.Size / sec.Entsize)
	for i := 0; i < nRels; i++ {
		off := i * int(sec.Entsize)
		rd := bytes.NewReader(data[off : off+int(sec.Entsize)])

		var rel elf.Rel64
		if binary.Read(rd, ec.ByteOrder, &rel) != nil {
			return errors.Errorf("section %v: cannot parse relocation %v", sec.Name, i)
		}

		sym, err := ec.symtab.forRelocation(rel)
		if err != nil {
			return errors.Errorf("section %v: relocation %v: %v", sec.Name, i, err.Error())
		}

		idx, ok := offsets[rel.Off]
		if !ok {
			return errors.Errorf("section %v: symbol %v: invalid instruction offset %x", sec.Name, sym, rel.Off)
		}
		insns[idx].Reference = sym.Name
	}
	return nil
}

type symtab struct {
	Symbols []elf.Symbol
	index   map[int]map[uint64]*elf.Symbol
}

func newSymtab(symbols []elf.Symbol) *symtab {
	index := make(map[int]map[uint64]*elf.Symbol)
	for i, sym := range symbols {
		if elf.ST_TYPE(sym.Info) != elf.STT_NOTYPE {
			continue
		}

		if sym.Name == "" {
			continue
		}

		idx := int(sym.Section)
		if _, ok := index[idx]; !ok {
			index[idx] = make(map[uint64]*elf.Symbol)
		}
		index[idx][sym.Value] = &symbols[i]
	}
	return &symtab{
		symbols,
		index,
	}
}

func (st *symtab) forSection(sec int) map[uint64]*elf.Symbol {
	return st.index[sec]
}

func (st *symtab) forSectionOffset(sec int, offset uint64) *elf.Symbol {
	offsets := st.index[sec]
	if offsets == nil {
		return nil
	}
	return offsets[offset]
}

func (st *symtab) forRelocation(rel elf.Rel64) (*elf.Symbol, error) {
	symNo := int(rel.Info>>32) - 1
	if symNo >= len(st.Symbols) {
		return nil, errors.Errorf("symbol %v doesnt exist", symNo)
	}
	return &st.Symbols[symNo], nil
}
