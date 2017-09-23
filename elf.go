// Copyright 2017 Nathan Sweet. All rights reserved.
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
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
}

type progSpec struct {
	*progCreateAttr
	licenseStr string
	instrs     *Instructions
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
	return p.licenseStr
}

func (p *progSpec) KernelVersion() uint32 {
	return p.kernelVersion
}

func GetSpecsFromELF(code io.ReaderAt) (map[string]BPFProgramSpec, map[string]BPFMapSpec, error) {
	progMap, mapMap, err := getSpecsFromELF(code)
	if err != nil {
		return nil, nil, err
	}
	pM := make(map[string]BPFProgramSpec)
	mM := make(map[string]BPFMapSpec)
	for k, v := range progMap {
		pM[k] = v
	}
	for k, v := range mapMap {
		mM[k] = v
	}
	return pM, mM, nil
}

func getSpecsFromELF(code io.ReaderAt) (programMap map[string]*progSpec, mapMap map[string]*mapSpec, err error) {
	programMap = make(map[string]*progSpec)
	mapMap = make(map[string]*mapSpec)
	var f *elf.File
	f, err = elf.NewFile(code)
	if err != nil {
		return
	}
	defer f.Close()
	byteOrder := f.ByteOrder
	var license string
	var version uint32
	var symbols []elf.Symbol
	sectionsLen := len(f.Sections)
	processedSections := make([]bool, sectionsLen)
	var maps *[]*mapSpec
	symbols, err = f.Symbols()
	if err != nil {
		return
	}
	symbolMap := make(map[string]string)
	for _, sym := range symbols {
		symbolMap[fmt.Sprintf("%d-%d", int(sym.Section), int(sym.Value))] = sym.Name
	}
	for i, sec := range f.Sections {
		var data []byte
		data, err = sec.Data()
		if err != nil {
			return
		}
		switch {
		case strings.Index(sec.Name, "license") == 0:
			license = string(data)
			processedSections[i] = true
		case strings.Index(sec.Name, "version") == 0:
			version = byteOrder.Uint32(data)
			processedSections[i] = true
		case strings.Index(sec.Name, "maps") == 0:
			maps, mapMap, err = loadMaps(byteOrder, data, i, symbolMap)
			if err != nil {
				return
			}
			processedSections[i] = true
		}
	}
	for i, sec := range f.Sections {
		if !processedSections[i] && sec.Type == elf.SHT_REL {
			if int(sec.Info) >= sectionsLen {
				err = fmt.Errorf("relocation section info, %d, larger than sections set size, %d, this program is missing sections", int(sec.Info), sectionsLen)
				return
			}
			var data []byte
			data, err = sec.Data()
			if err != nil {
				return
			}
			sec2 := f.Sections[sec.Info]
			if sec2.Type == elf.SHT_PROGBITS &&
				sec2.Flags&elf.SHF_EXECINSTR > 0 {
				var data2 []byte
				data2, err = sec2.Data()
				if err != nil {
					return
				}
				insns := loadInstructions(byteOrder, data2, sec2.Name)
				err = parseRelocateApply(byteOrder, data, symbols, sec, insns, maps)
				if err != nil {
					return
				}
				processedSections[i] = true
				processedSections[sec.Info] = true
				progType := getProgType(sec2.Name)
				if progType != ProgTypeUnrecognized {
					progSpec := &progSpec{
						progCreateAttr: &progCreateAttr{
							progType:      progType,
							kernelVersion: version,
						},
						licenseStr: license,
						instrs:     insns,
					}
					if name, ok := symbolMap[fmt.Sprintf("%d-0", int(sec.Info))]; ok && len(name) > 0 {
						programMap[replaceForwardSlash(name)] = progSpec
					} else {
						err = fmt.Errorf("program section had no symbol; invalid bpf binary")
						return
					}
				}
			}
		}
	}

	for i, sec := range f.Sections {
		if !processedSections[i] && sec.Type != elf.SHT_SYMTAB &&
			len(sec.Name) > 0 && sec.Size > 0 {
			var data []byte
			data, err = sec.Data()
			if err != nil {
				return
			}
			progType := getProgType(sec.Name)
			if progType != ProgTypeUnrecognized && len(data) > 0 {
				insns := loadInstructions(byteOrder, data, sec.Name)
				progSpec := &progSpec{
					progCreateAttr: &progCreateAttr{
						progType:      progType,
						kernelVersion: version,
					},
					licenseStr: license,
					instrs:     insns,
				}
				if name, ok := symbolMap[fmt.Sprintf("%d-0", int(sec.Info))]; ok && len(name) > 0 {
					programMap[replaceForwardSlash(name)] = progSpec
				} else {
					err = fmt.Errorf("program section had no symbol; invalid bpf binary")
					return
				}
			}
		}
	}
	return
}

func dataToString(data []byte) string {
	buf := bytes.NewBuffer(nil)
	for _, byt := range data {
		buf.WriteString(fmt.Sprintf("0x%x ", byt))
	}
	return buf.String()
}

func loadMaps(byteOrder binary.ByteOrder, data []byte, section int, symbolMap map[string]string) (*[]*mapSpec, map[string]*mapSpec, error) {
	var maps []*mapSpec
	mapMap := make(map[string]*mapSpec)
	for i := 0; i < len(data); i += 4 {
		t := i
		mT := MapType(byteOrder.Uint32(data[i : i+4]))
		i += 4
		kS := byteOrder.Uint32(data[i : i+4])
		i += 4
		vS := byteOrder.Uint32(data[i : i+4])
		i += 4
		mE := byteOrder.Uint32(data[i : i+4])
		i += 4
		fl := byteOrder.Uint32(data[i : i+4])
		bMap := &mapSpec{
			mapCreateAttr: &mapCreateAttr{
				mapType:    mT,
				keySize:    kS,
				valueSize:  vS,
				maxEntries: mE,
				flags:      fl,
			},
		}
		maps = append(maps, bMap)
		if name, ok := symbolMap[fmt.Sprintf("%d-%d", section, t)]; ok && len(name) > 0 {
			mapMap[replaceForwardSlash(name)] = bMap
		}
	}
	return &maps, mapMap, nil
}

func getProgType(v string) ProgType {
	types := map[string]ProgType{
		"socket":      ProgTypeSocketFilter,
		"kprobe/":     ProgTypeKprobe,
		"kretprobe/":  ProgTypeKprobe,
		"tracepoint/": ProgTypeTracePoint,
		"xdp":         ProgTypeXDP,
		"perf_event":  ProgTypePerfEvent,
		"cgroup/skb":  ProgTypeCGroupSKB,
		"cgroup/sock": ProgTypeCGroupSock,
	}
	for k, t := range types {
		if strings.Index(v, k) == 0 {
			return t
		}
	}
	return ProgTypeUnrecognized
}

func loadInstructions(byteOrder binary.ByteOrder, data []byte, sectionName string) *Instructions {
	var insns Instructions
	dataLen := len(data)
	for i := 0; i < dataLen; i += 8 {
		var sn string
		if i == 0 {
			sn = sectionName
		}
		regs := bitField(data[i+1])
		var off int16
		binary.Read(bytes.NewBuffer(data[i+2:i+4]), byteOrder, &off)
		var imm int32
		binary.Read(bytes.NewBuffer(data[i+4:i+8]), byteOrder, &imm)
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

func parseRelocateApply(byteOrder binary.ByteOrder, data []byte, symbols []elf.Symbol, sec *elf.Section, insns *Instructions, maps *[]*mapSpec) error {
	nRels := int(sec.Size / sec.Entsize)
	for i, t := 0, 0; i < nRels; i++ {
		rel := elf.Rela64{
			Off:  byteOrder.Uint64(data[t : t+8]),
			Info: byteOrder.Uint64(data[t+8 : t+16]),
		}
		t += 24
		symNo := int(rel.Info>>32) - 1
		if symNo == 0 || symNo >= len(symbols) {
			return fmt.Errorf("index calculated from rel index, %d, is greater than the symbol set, %d or is 0; the source was probably compiled for another architecture", symNo, len(symbols))
		}
		// value / sizeof(bpf_map_def)
		mapIdx := int(symbols[symNo].Value / 24)
		if maps == nil || mapIdx >= len(*maps) {
			return fmt.Errorf("index calculated from symbol value is greater than the map set; the source was probably compiled with bad symbols")
		}
		mapSpec := (*maps)[mapIdx]
		// offset / sizeof(bpfInstruction)
		idx := int(rel.Off / 8)
		if insns == nil || idx >= len(*insns) {
			return fmt.Errorf("index calculated from rel offset is greater than the instruction set; the source was probably compiled for another architecture")
		}
		ins := (*insns)[idx]
		if ins.OpCode != LdDW {
			return fmt.Errorf("the only valid relocation command is for loading a map file descriptor")
		}
		mapSpec.instructionReplacements = append(mapSpec.instructionReplacements, ins)
	}
	return nil
}

func replaceForwardSlash(s string) string {
	return strings.Replace(s, "/", "_slash_", -1)
}

func unReplaceForwardSlash(s string) string {
	return strings.Replace(s, "_slash_", "/", -1)
}
