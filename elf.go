package ebpf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

type mapSpec struct {
	mapCreateAttr
	key string
}

type progSpec struct {
	progType     ProgType
	license      string
	instrs       Instructions
	key          string
	version      uint32
	replacements map[string][]*BPFInstruction
}

type elfCode struct {
	*elf.File
	symbols     []elf.Symbol
	symbolNames map[int]map[uint64]string
}

func (m *mapSpec) MapType() MapType {
	return m.mapType
}

func (m *mapSpec) KeySize() uint32 {
	return m.keySize
}

func (m *mapSpec) ValueSize() uint32 {
	return m.valueSize
}

func (m *mapSpec) MaxEntries() uint32 {
	return m.maxEntries
}

func (m *mapSpec) Flags() uint32 {
	return m.flags
}

func (p *progSpec) ProgType() ProgType {
	return p.progType
}

func (p *progSpec) Instructions() Instructions {
	return p.instrs
}

func (p *progSpec) License() string {
	return p.license
}

func (p *progSpec) KernelVersion() uint32 {
	return p.version
}

// GetSpecsFromELF parses an io.ReaderAt that represents and ELF layout, and categorizes the code
// and maps by symbol
func GetSpecsFromELF(code io.ReaderAt) (map[string]ProgramSpec, map[string]MapSpec, error) {
	progMap, mapMap, err := getSpecsFromELF(code)
	if err != nil {
		return nil, nil, err
	}
	pM := make(map[string]ProgramSpec)
	mM := make(map[string]MapSpec)
	for k, v := range progMap {
		pM[k] = v
	}
	for k, v := range mapMap {
		mM[k] = v
	}
	return pM, mM, nil
}

func getSpecsFromELF(code io.ReaderAt) (map[string]*progSpec, map[string]*mapSpec, error) {
	var f *elf.File
	f, err := elf.NewFile(code)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()

	ec := &elfCode{
		f,
		nil,
		make(map[int]map[uint64]string),
	}

	ec.symbols, err = f.Symbols()
	if err != nil {
		return nil, nil, err
	}

	for _, sym := range ec.symbols {
		idx := int(sym.Section)
		if int(sym.Section) > len(ec.Sections) {
			return nil, nil, fmt.Errorf("symbol %v: unknown section %v", sym.Name, sym.Section)
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
				return nil, nil, fmt.Errorf("found relocation section %v for missing section %v", i, sec.Info)
			}

			// Store relocations under the section index of the target
			idx := int(sec.Info)
			if relSections[idx] != nil {
				return nil, nil, fmt.Errorf("section %d has multiple relocation sections", idx)
			}
			relSections[idx] = sec
		case sec.Type != elf.SHT_SYMTAB && sec.Type != elf.SHT_NULL && len(sec.Name) > 0 && sec.Size > 0:
			progSections[i] = sec
		}
	}

	license, err := loadLicense(licenseSection)
	if err != nil {
		return nil, nil, err
	}

	version, err := loadVersion(versionSection, ec.ByteOrder)
	if err != nil {
		return nil, nil, err
	}

	maps, err := ec.loadMaps(mapSections)
	if err != nil {
		return nil, nil, err
	}

	progs := make(map[string]*progSpec)
	for i, prog := range progSections {
		spec, err := ec.loadProg(i, prog, relSections[i], license, version)
		if err != nil {
			return nil, nil, err
		}

		if spec == nil {
			continue
		}

		progs[spec.key] = spec
	}

	return progs, maps, nil
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

func (ec *elfCode) loadProg(idx int, prog, rels *elf.Section, license string, version uint32) (*progSpec, error) {
	data, err := prog.Data()
	if err != nil {
		return nil, err
	}
	progType := getProgType(prog.Name)
	if progType == Unrecognized {
		return nil, nil
	}
	insns, err := ec.loadInstructions(data, prog.Name)
	if err != nil {
		return nil, err
	}
	key, err := ec.getSecSymbolName(idx, 0)
	if err != nil {
		return nil, err
	}
	spec := &progSpec{
		progType:     progType,
		key:          key,
		license:      license,
		version:      version,
		instrs:       insns,
		replacements: make(map[string][]*BPFInstruction),
	}
	if rels == nil {
		return spec, nil
	}
	err = ec.parseRelocateApply(spec, rels)
	if err != nil {
		return nil, err
	}
	return spec, nil
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

func (ec *elfCode) loadMaps(mapSections map[int]*elf.Section) (map[string]*mapSpec, error) {
	maps := make(map[string]*mapSpec)
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
		for i := 0; i < n; i++ {
			rd := bytes.NewReader(data[i*size : i*size+size])
			name, err := ec.getSecSymbolName(idx, uint64(i*size))
			if err != nil {
				return nil, err
			}

			if maps[name] != nil {
				return nil, fmt.Errorf("section %v: map %v already exists", sec.Name, name)
			}

			bMap := mapSpec{key: name}
			switch {
			case binary.Read(rd, ec.ByteOrder, &bMap.mapType) != nil:
				return nil, fmt.Errorf("map %v: missing type", name)
			case binary.Read(rd, ec.ByteOrder, &bMap.keySize) != nil:
				return nil, fmt.Errorf("map %v: missing key size", name)
			case binary.Read(rd, ec.ByteOrder, &bMap.valueSize) != nil:
				return nil, fmt.Errorf("map %v: missing value size", name)
			case binary.Read(rd, ec.ByteOrder, &bMap.maxEntries) != nil:
				return nil, fmt.Errorf("map %v: missing max entries", name)
			case binary.Read(rd, ec.ByteOrder, &bMap.flags) != nil:
				return nil, fmt.Errorf("map %v: missing flags", name)
			}
			if rd.Len() != 0 {
				return nil, fmt.Errorf("map %v: unknown fields in definition", name)
			}
			maps[name] = &bMap
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

func (ec *elfCode) parseRelocateApply(spec *progSpec, sec *elf.Section) error {
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

		// offset / sizeof(bpfInstruction)
		idx := int(rel.Offset / 8)
		if idx >= len(spec.instrs) {
			return fmt.Errorf("index calculated from rel offset is greater than the instruction set; the source was probably compiled for another architecture")
		}

		ins := spec.instrs[idx]
		if ins.OpCode != LdDW {
			return fmt.Errorf("the only valid relocation command is for loading a map file descriptor")
		}

		symNo := int(rel.Info>>32) - 1
		if symNo == 0 || symNo >= len(ec.symbols) {
			return fmt.Errorf("section %v: relocation %v: symbol %v doesnt exist", sec.Name, i, symNo)
		}

		sym := ec.symbols[symNo].Name
		spec.replacements[sym] = append(spec.replacements[sym], ins)
	}
	return nil
}
