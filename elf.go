package ebpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

type elfCode struct {
	*elf.File
	symbols     []elf.Symbol
	symbolNames map[int]map[uint64]string
}

// NewCollectionSpecFromELF parses an io.ReaderAt that represents an ELF layout
// into a CollectionSpec.
func NewCollectionSpecFromELF(code io.ReaderAt) (*CollectionSpec, error) {
	f, err := elf.NewFile(code)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	ec := &elfCode{
		f,
		nil,
		make(map[int]map[uint64]string),
	}

	ec.symbols, err = f.Symbols()
	if err != nil {
		return nil, err
	}

	for _, sym := range ec.symbols {
		idx := int(sym.Section)
		// SHN_COMMON are symbols which are declared, but not allocated.
		// They are valid targets for rewriting, so make an exception for them.
		if idx > len(ec.Sections) && sym.Section != elf.SHN_COMMON {
			return nil, fmt.Errorf("symbol %v: unknown section %v", sym.Name, sym.Section)
		}
		if _, ok := ec.symbolNames[idx]; !ok {
			ec.symbolNames[idx] = make(map[uint64]string)
		}
		ec.symbolNames[idx][sym.Value] = sym.Name
	}

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
				return nil, fmt.Errorf("found relocation section %v for missing section %v", i, sec.Info)
			}

			// Store relocations under the section index of the target
			idx := int(sec.Info)
			if relSections[idx] != nil {
				return nil, fmt.Errorf("section %d has multiple relocation sections", idx)
			}
			relSections[idx] = sec
		case sec.Type != elf.SHT_SYMTAB && sec.Type != elf.SHT_NULL && len(sec.Name) > 0 && sec.Size > 0:
			progSections[i] = sec
		}
	}

	license, err := loadLicense(licenseSection)
	if err != nil {
		return nil, err
	}

	version, err := loadVersion(versionSection, ec.ByteOrder)
	if err != nil {
		return nil, err
	}

	maps, err := ec.loadMaps(mapSections)
	if err != nil {
		return nil, err
	}

	progs := make(map[string]*ProgramSpec)
	for i, prog := range progSections {
		name, spec, err := ec.loadProg(i, prog, relSections[i], license, version)
		if err != nil {
			return nil, err
		}

		if spec == nil {
			continue
		}

		progs[name] = spec
	}

	return &CollectionSpec{maps, progs}, nil
}

func loadLicense(sec *elf.Section) (string, error) {
	if sec == nil {
		return "", fmt.Errorf("missing license section")
	}
	data, err := sec.Data()
	if err != nil {
		return "", err
	}
	return string(bytes.TrimRight(data, "\000")), nil
}

func loadVersion(sec *elf.Section, bo binary.ByteOrder) (uint32, error) {
	if sec == nil {
		return 0, nil
	}
	data, err := sec.Data()
	if err != nil {
		return 0, err
	}
	var version uint32
	return version, binary.Read(bytes.NewReader(data), bo, &version)
}

func (ec *elfCode) loadProg(idx int, prog, rels *elf.Section, license string, version uint32) (string, *ProgramSpec, error) {
	data, err := prog.Data()
	if err != nil {
		return "", nil, err
	}
	progType := getProgType(prog.Name)
	if progType == Unrecognized {
		return "", nil, nil
	}
	insns, err := ec.loadInstructions(data, prog.Name)
	if err != nil {
		return "", nil, err
	}
	key, err := ec.getSecSymbolName(idx, 0)
	if err != nil {
		return "", nil, err
	}
	spec := &ProgramSpec{
		Type:          progType,
		License:       license,
		KernelVersion: version,
		Instructions:  insns,
	}
	if rels == nil {
		return key, spec, nil
	}
	spec.Refs = make(map[string][]*BPFInstruction)
	err = ec.parseRelocateApply(spec, rels)
	if err != nil {
		return "", nil, err
	}
	return key, spec, nil
}

func (ec *elfCode) getSecSymbolName(idx int, off uint64) (string, error) {
	sec, ok := ec.symbolNames[idx]
	if !ok {
		return "", fmt.Errorf("unknown section %v", idx)
	}

	name, ok := sec[off]
	if !ok {
		return "", fmt.Errorf("section %v: no symbol at offset %v", idx, off)
	}

	return name, nil
}

func dataToString(data []byte) string {
	buf := bytes.NewBuffer(nil)
	for _, byt := range data {
		buf.WriteString(fmt.Sprintf("0x%x ", byt))
	}
	return buf.String()
}

func (ec *elfCode) loadMaps(mapSections map[int]*elf.Section) (map[string]*MapSpec, error) {
	maps := make(map[string]*MapSpec)
	for idx, sec := range mapSections {
		n := len(ec.symbolNames[idx])
		if n == 0 {
			return nil, fmt.Errorf("section %v: no symbols", sec.Name)
		}

		data, err := sec.Data()
		if err != nil {
			return nil, err
		}

		if len(data)%n != 0 {
			return nil, fmt.Errorf("map descriptors are not of equal size")
		}

		size := len(data) / n
		var ordered []*MapSpec
		for i := 0; i < n; i++ {
			rd := bytes.NewReader(data[i*size : i*size+size])
			name, err := ec.getSecSymbolName(idx, uint64(i*size))
			if err != nil {
				return nil, err
			}

			if maps[name] != nil {
				return nil, fmt.Errorf("section %v: map %v already exists", sec.Name, name)
			}

			var spec MapSpec
			var inner uint32
			switch {
			case binary.Read(rd, ec.ByteOrder, &spec.Type) != nil:
				return nil, fmt.Errorf("map %v: missing type", name)
			case binary.Read(rd, ec.ByteOrder, &spec.KeySize) != nil:
				return nil, fmt.Errorf("map %v: missing key size", name)
			case binary.Read(rd, ec.ByteOrder, &spec.ValueSize) != nil:
				return nil, fmt.Errorf("map %v: missing value size", name)
			case binary.Read(rd, ec.ByteOrder, &spec.MaxEntries) != nil:
				return nil, fmt.Errorf("map %v: missing max entries", name)
			case binary.Read(rd, ec.ByteOrder, &spec.Flags) != nil:
				return nil, fmt.Errorf("map %v: missing flags", name)
			case rd.Len() > 0 && binary.Read(rd, ec.ByteOrder, &inner) != nil:
				return nil, fmt.Errorf("map %v: can't read inner map index", name)
			}

			if rd.Len() != 0 {
				return nil, fmt.Errorf("map %v: unknown fields in definition", name)
			}

			if spec.Type == ArrayOfMaps || spec.Type == HashOfMaps {
				if int(inner) > len(ordered) {
					return nil, fmt.Errorf("map %v: invalid inner map index %d", name, inner)
				}

				innerSpec := ordered[int(inner)]
				if innerSpec.InnerMap != nil {
					return nil, fmt.Errorf("map %v: can't nest map of map", name)
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
		"socket":      SocketFilter,
		"seccomp":     SocketFilter,
		"kprobe/":     Kprobe,
		"kretprobe/":  Kprobe,
		"tracepoint/": TracePoint,
		"xdp":         XDP,
		"perf_event":  PerfEvent,
		"cgroup/skb":  CGroupSKB,
		"cgroup/sock": CGroupSock,
	}
	for k, t := range types {
		if strings.Index(v, k) == 0 {
			return t
		}
	}
	return Unrecognized
}

func (ec *elfCode) loadInstructions(data []byte, sectionName string) (Instructions, error) {
	rd := bytes.NewReader(data)
	firstInsnSection := sectionName
	var insns Instructions
	for rd.Len() > 0 {
		var ins bpfInstruction
		if err := binary.Read(rd, ec.ByteOrder, &ins); err != nil {
			return nil, fmt.Errorf("program %v: invalid instruction at offset %x", sectionName, rd.Size()-int64(rd.Len()))
		}
		insns = append(insns, &BPFInstruction{
			OpCode:      ins.OpCode,
			DstRegister: ins.Registers.GetPart1(),
			SrcRegister: ins.Registers.GetPart2(),
			Offset:      ins.Offset,
			Constant:    ins.Constant,
			sectionName: firstInsnSection,
		})
		// Only set section name on the first entry
		firstInsnSection = ""
	}
	return insns, nil
}

func (ec *elfCode) parseRelocateApply(spec *ProgramSpec, sec *elf.Section) error {
	if sec.Entsize < 16 {
		return fmt.Errorf("section %v: rls are less than 16 bytes", sec.Name)
	}

	data, err := sec.Data()
	if err != nil {
		return err
	}

	nRels := int(sec.Size / sec.Entsize)
	for i := 0; i < nRels; i++ {
		off := i * int(sec.Entsize)
		rd := bytes.NewReader(data[off : off+int(sec.Entsize)])

		var rel struct {
			// Offset of the relocation in the targeted section
			Offset uint64
			// symbol number
			Info uint64
		}
		if binary.Read(rd, ec.ByteOrder, &rel) != nil {
			return fmt.Errorf("section %v: cannot parse relocation %v", sec.Name, i)
		}

		symNo := int(rel.Info>>32) - 1
		if symNo == 0 || symNo >= len(ec.symbols) {
			return fmt.Errorf("section %v: relocation %v: symbol %v doesnt exist", sec.Name, i, symNo)
		}
		sym := ec.symbols[symNo].Name

		idx := int(rel.Offset / InstructionSize)
		if idx >= len(spec.Instructions) {
			return fmt.Errorf("section %v: symbol %v: invalid instruction offset", sec.Name, sym)
		}
		ins := spec.Instructions[idx]

		spec.Refs[sym] = append(spec.Refs[sym], ins)
	}
	return nil
}
