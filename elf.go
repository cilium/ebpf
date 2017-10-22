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
	*mapCreateAttr
	instructionReplacements []*BPFInstruction
	key                     string
}

type progSpec struct {
	progType   ProgType
	licenseStr *string
	instrs     *Instructions
	key        string
	kVersion   *uint32
}

type elfCode struct {
	*elf.File
	license         *string
	version         *uint32
	symbols         []elf.Symbol
	symbolMap       map[string]string
	symbolsLen      int
	mapReplacements map[int][]*BPFInstruction
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

func (p *progSpec) Instructions() *Instructions {
	return p.instrs
}

func (p *progSpec) License() string {
	return *p.licenseStr
}

func (p *progSpec) KernelVersion() uint32 {
	return *p.kVersion
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
	for _, v := range progMap {
		pM[v.key] = v
	}
	for _, v := range mapMap {
		mM[v.key] = v
	}
	return pM, mM, nil
}

func getSpecsFromELF(code io.ReaderAt) (programs []*progSpec, maps []*mapSpec, err error) {
	var f *elf.File
	f, err = elf.NewFile(code)
	if err != nil {
		return
	}
	defer f.Close()
	var l string
	var v uint32
	ec := &elfCode{
		f,
		&l,
		&v,
		nil,
		make(map[string]string),
		0,
		make(map[int][]*BPFInstruction),
	}
	ec.symbols, err = f.Symbols()
	if err != nil {
		return
	}
	ec.symbolsLen = len(ec.symbols)
	for _, sym := range ec.symbols {
		ec.symbolMap[fmt.Sprintf("%d-%d", int(sym.Section), int(sym.Value))] = sym.Name
	}
	sectionsLen := len(ec.Sections)
	for i, sec := range ec.Sections {
		fmt.Println(i, sec.Info)
		var data []byte
		data, err = sec.Data()
		if err != nil {
			return
		}
		switch {
		case strings.Index(sec.Name, "license") == 0:
			*ec.license = string(data)
		case strings.Index(sec.Name, "version") == 0:
			*ec.version = ec.ByteOrder.Uint32(data)
		case strings.Index(sec.Name, "maps") == 0:
			maps, err = ec.loadMaps(data, uint32(i))
			if err != nil {
				return
			}
		case sec.Type == elf.SHT_REL:
			if int(sec.Info) >= sectionsLen {
				err = fmt.Errorf("relocation section info, %d, larger than sections set size, %d, this program is missing sections", int(sec.Info), sectionsLen)
				return
			}
			sec2 := f.Sections[sec.Info]
			if sec2.Type == elf.SHT_PROGBITS &&
				sec2.Flags&elf.SHF_EXECINSTR > 0 {
				var prog *progSpec
				prog, err = ec.loadProg(sec2, nil)
				if err != nil {
					return
				}
				if prog != nil {
					var name string
					name, err = ec.getSecSymbolName(sec.Info, 0)
					if err != nil {
						return
					}
					prog.key = name
					err = ec.parseRelocateApply(data, sec, prog.instrs)
					if err != nil {
						return
					}
					programs = append(programs, prog)
				}
			}
		case sec.Type != elf.SHT_SYMTAB && len(sec.Name) > 0 && sec.Size > 0:
			var prog *progSpec
			prog, err = ec.loadProg(sec, data)
			if err != nil {
				return
			}
			if prog != nil {
				var name string
				name, err = ec.getSecSymbolName(sec.Info, 0)
				if err != nil {
					return
				}
				prog.key = name
				programs = append(programs, prog)
			}
		}
	}
	mapLen := len(maps)
	for i, rep := range ec.mapReplacements {
		if i >= mapLen {
			err = fmt.Errorf("index calculated from symbol value is greater than the map set; the source was probably compiled with bad symbols")
			return
		}
		mapSpec := maps[i]
		mapSpec.instructionReplacements = rep
	}
	return
}

func (ec *elfCode) loadProg(sec *elf.Section, data []byte) (*progSpec, error) {
	if len(data) == 0 {
		var err error
		data, err = sec.Data()
		if err != nil {
			return nil, err
		}
	}
	progType := getProgType(sec.Name)
	if progType != Unrecognized && len(data) > 0 {
		insns := ec.loadInstructions(data, sec.Name)
		progSpec := &progSpec{
			progType:   progType,
			licenseStr: ec.license,
			kVersion:   ec.version,
			instrs:     insns,
		}
		return progSpec, nil
	}
	return nil, nil
}

func (ec *elfCode) getSecSymbolName(sec uint32, off int) (string, error) {
	if name, ok := ec.symbolMap[fmt.Sprintf("%d-%d", sec, off)]; ok && len(name) > 0 {
		return name, nil
	}
	return "", fmt.Errorf("section had no symbol; invalid bpf binary")
}

func dataToString(data []byte) string {
	buf := bytes.NewBuffer(nil)
	for _, byt := range data {
		buf.WriteString(fmt.Sprintf("0x%x ", byt))
	}
	return buf.String()
}

func (ec *elfCode) loadMaps(data []byte, section uint32) ([]*mapSpec, error) {
	var maps []*mapSpec
	for i := 0; i < len(data); i += 4 {
		t := i
		mT := MapType(ec.ByteOrder.Uint32(data[i : i+4]))
		i += 4
		kS := ec.ByteOrder.Uint32(data[i : i+4])
		i += 4
		vS := ec.ByteOrder.Uint32(data[i : i+4])
		i += 4
		mE := ec.ByteOrder.Uint32(data[i : i+4])
		i += 4
		fl := ec.ByteOrder.Uint32(data[i : i+4])
		bMap := &mapSpec{
			mapCreateAttr: &mapCreateAttr{
				mapType:    mT,
				keySize:    kS,
				valueSize:  vS,
				maxEntries: mE,
				flags:      fl,
			},
		}
		name, err := ec.getSecSymbolName(section, t)
		if err != nil {
			return nil, err
		}
		bMap.key = name
		maps = append(maps, bMap)
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

func (ec *elfCode) loadInstructions(data []byte, sectionName string) *Instructions {
	var insns Instructions
	dataLen := len(data)
	for i := 0; i < dataLen; i += 8 {
		var sn string
		if i == 0 {
			sn = sectionName
		}
		regs := bitField(data[i+1])
		var off int16
		binary.Read(bytes.NewBuffer(data[i+2:i+4]), ec.ByteOrder, &off)
		var imm int32
		binary.Read(bytes.NewBuffer(data[i+4:i+8]), ec.ByteOrder, &imm)
		ins := &BPFInstruction{
			OpCode:      data[i],
			DstRegister: regs.GetPart1(),
			SrcRegister: regs.GetPart2(),
			Offset:      off,
			Constant:    imm,
			sectionName: sn,
		}
		insns = append(insns, ins)
	}
	return &insns
}

func (ec *elfCode) parseRelocateApply(data []byte, sec *elf.Section, insns *Instructions) error {
	nRels := int(sec.Size / sec.Entsize)
	for i, t := 0, 0; i < nRels; i++ {
		rel := elf.Rela64{
			Off:  ec.ByteOrder.Uint64(data[t : t+8]),
			Info: ec.ByteOrder.Uint64(data[t+8 : t+16]),
		}
		t += 24
		symNo := int(rel.Info>>32) - 1
		if symNo == 0 || symNo >= ec.symbolsLen {
			return fmt.Errorf("index calculated from rel index, %d, is greater than the symbol set, %d or is 0; the source was probably compiled for another architecture", symNo, ec.symbolsLen)
		}
		// offset / sizeof(bpfInstruction)
		idx := int(rel.Off / 8)
		if insns == nil || idx >= len(*insns) {
			return fmt.Errorf("index calculated from rel offset is greater than the instruction set; the source was probably compiled for another architecture")
		}
		ins := (*insns)[idx]
		if ins.OpCode != LdDW {
			return fmt.Errorf("the only valid relocation command is for loading a map file descriptor")
		}
		// value / sizeof(bpf_map_def)
		mapIdx := int(ec.symbols[symNo].Value / 24)
		ec.mapReplacements[mapIdx] = append(ec.mapReplacements[mapIdx], ins)
	}
	return nil
}
