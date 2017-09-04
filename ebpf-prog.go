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
	"os"
	"strings"
	"unsafe"
)

type BPFProgram struct {
	fd            int
	logs          []byte
	instructions  *Instructions
	kernelVersion uint32
	license       string
	progType      ProgType
	sectionName   string
}

func NewBPFProgram(progType ProgType, instructions *Instructions, license string, kernelVersion uint32) (*BPFProgram, error) {
	var sn string
	if instructions != nil && len(*instructions) > 0 && len((*instructions)[0].sectionName) > 0 {
		sn = (*instructions)[0].sectionName
	}
	bpf := &BPFProgram{
		instructions:  instructions,
		kernelVersion: kernelVersion,
		license:       license,
		progType:      progType,
		sectionName:   sn,
	}
	var cInstructions []bpfInstruction
	for _, ins := range *bpf.instructions {
		inss := ins.getCStructs()
		for _, ins2 := range inss {
			cInstructions = append(cInstructions, ins2)
		}
	}
	insCount := uint32(len(cInstructions))
	if insCount > MaxBPFInstructions {
		return nil, fmt.Errorf("max instructions, %s, exceeded", MaxBPFInstructions)
	}
	lic := []byte(bpf.license)
	logs := make([]byte, LogBufSize)
	fd, e := bpfCall(_BPF_PROG_LOAD, unsafe.Pointer((&struct {
		progType      uint32
		insCount      uint32
		instructions  uint64
		license       uint64
		logLevel      uint32
		logSize       uint32
		logBuf        uint64
		kernelVersion uint32
		padding       uint32
	}{
		progType:     uint32(bpf.progType),
		insCount:     insCount,
		instructions: uint64(uintptr(unsafe.Pointer(&cInstructions[0]))),
		license:      uint64(uintptr(unsafe.Pointer(&lic[0]))),
		logLevel:     1,
		logSize:      LogBufSize,
		logBuf:       uint64(uintptr(unsafe.Pointer(&logs[0]))),
	})), 48)
	if e != 0 {
		if len(logs) > 0 {
			return nil, fmt.Errorf("%s:\n\t%s", errnoErr(e), strings.Replace(string(logs), "\n", "\n\t", -1))
		}
		return nil, errnoErr(e)
	}
	bpf.fd = int(fd)
	bpf.logs = logs
	return bpf, nil
}

func (bpf *BPFProgram) GetLogs() string {
	return string(bpf.logs)
}

func (bpf *BPFProgram) GetFd() int {
	return bpf.fd
}

func (bpf *BPFProgram) GetInstructions() *Instructions {
	return bpf.instructions
}

func (bpf *BPFProgram) GetKernelVersion() uint32 {
	return bpf.kernelVersion
}

type BPFCollection struct {
	programs *[]*BPFProgram
	maps     *[]*BPFMap
}

func (coll *BPFCollection) GetMaps() *[]*BPFMap {
	return coll.maps
}

func (coll *BPFCollection) GetPrograms() *[]*BPFProgram {
	return coll.programs
}

func NewBPFCollectionFromFile(file string) (*BPFCollection, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return NewBPFCollectionFromObjectCode(f)
}

func NewBPFCollectionFromObjectCode(code io.ReaderAt) (*BPFCollection, error) {
	f, err := elf.NewFile(code)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	byteOrder := f.ByteOrder
	var license string
	var version uint32
	var maps *[]*BPFMap
	var symbols []elf.Symbol
	sectionsLen := len(f.Sections)
	processedSections := make([]bool, sectionsLen)
	for i, sec := range f.Sections {
		data, err := sec.Data()
		if err != nil {
			return nil, err
		}
		switch sec.Name {
		case "license":
			license = string(data)
			processedSections[i] = true
		case "version":
			version = byteOrder.Uint32(data)
			processedSections[i] = true
		case "maps":
			maps, err = loadMaps(byteOrder, data)
			if err != nil {
				return nil, err
			}
			processedSections[i] = true
		}
	}
	symbols, err = f.Symbols()
	if err != nil {
		return nil, err
	}
	var programs []*BPFProgram
	for i, sec := range f.Sections {
		if !processedSections[i] && sec.Type == elf.SHT_REL {
			if int(sec.Info) < sectionsLen {
				return nil, fmt.Errorf("relocation section info greater than sections set, this program is missing sections")
			}
			data, err := sec.Data()
			if err != nil {
				return nil, err
			}
			sec2 := f.Sections[sec.Info]
			if sec2.Type == elf.SHT_PROGBITS &&
				sec2.Flags&elf.SHF_EXECINSTR > 0 {
				data2, err := sec2.Data()
				if err != nil {
					return nil, err
				}
				insns := loadInstructions(byteOrder, data2, sec2.Name)
				err = parseRelocateApply(byteOrder, data, symbols, sec, insns, maps)
				if err != nil {
					return nil, err
				}
				progType, err := getSectionType(sec2.Name)
				if err != nil {
					return nil, err
				}
				prog, err := NewBPFProgram(progType, insns, license, version)
				if err != nil {
					return nil, err
				}
				programs = append(programs, prog)
				processedSections[sec.Info] = true

			}
			processedSections[i] = true
		}
	}
	for i, sec := range f.Sections {
		if !processedSections[i] {
			data, err := sec.Data()
			if err != nil {
				return nil, err
			}
			insns := loadInstructions(byteOrder, data, sec.Name)
			progType, err := getSectionType(sec.Name)
			if err != nil {
				return nil, err
			}
			prog, err := NewBPFProgram(progType, insns, license, version)
			if err != nil {
				return nil, err
			}
			programs = append(programs, prog)
		}
	}
	return &BPFCollection{
		programs: &programs,
		maps:     maps,
	}, nil
}

func dataToString(data []byte) string {
	buf := bytes.NewBuffer(nil)
	for _, byt := range data {
		buf.WriteString(fmt.Sprintf("0x%x ", byt))
	}
	return buf.String()
}

func loadMaps(byteOrder binary.ByteOrder, data []byte) (*[]*BPFMap, error) {
	var maps []*BPFMap
	for i := 0; i < len(data); i += 4 {
		mT := MapType(byteOrder.Uint32(data[i : i+4]))
		i += 4
		kS := byteOrder.Uint32(data[i : i+4])
		i += 4
		vS := byteOrder.Uint32(data[i : i+4])
		i += 4
		mE := byteOrder.Uint32(data[i : i+4])
		i += 4
		fl := byteOrder.Uint32(data[i : i+4])
		bMap, err := NewBPFMap(mT, kS, vS, mE, fl)
		if err != nil {
			return nil, err
		}
		maps = append(maps, bMap)
	}
	return &maps, nil
}

func getSectionType(v string) (ProgType, error) {
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
			return t, nil
		}
	}
	return ProgType(0), fmt.Errorf("unrecognized type %s", v)
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
		uOff := byteOrder.Uint16(data[i+2 : i+4])
		s := uOff & 0x8000
		off := int16(uOff & 0x7FFF)
		if s > 0 {
			off = -off
		}
		uImm := byteOrder.Uint32(data[i+4 : i+8])
		s2 := uImm & 0x80000000
		imm := int32(uImm & 0x7FFFFFFF)
		if s2 > 0 {
			imm = -imm
		}
		insns = append(insns, &BPFInstruction{
			OpCode:      data[i],
			DstRegister: regs.GetPart1(),
			SrcRegister: regs.GetPart2(),
			Offset:      off,
			Constant:    imm,
			sectionName: sn,
		})
	}
	return &insns
}

func parseRelocateApply(byteOrder binary.ByteOrder, data []byte, symbols []elf.Symbol, sec *elf.Section, insns *Instructions, maps *[]*BPFMap) error {
	nRels := int(sec.Size / sec.Entsize)
	for i, t := 0, 0; i < nRels; i++ {
		rel := elf.Rela64{
			Off:  byteOrder.Uint64(data[t : t+8]),
			Info: byteOrder.Uint64(data[t+8 : t+16]),
		}
		t += 24
		if int(rel.Info) >= len(symbols) {
			return fmt.Errorf("index calculated from rel index is greater than the symbol set; the source was probably compiled for another architecture")
		}
		// value / sizeof(bpf_map_def)
		mapIdx := int(symbols[rel.Info].Value / 24)
		if maps == nil || mapIdx >= len(*maps) {
			return fmt.Errorf("index calculated from symbol value is greater than the map set; the source was probably compiled with bad symbols")
		}
		mapFd := (*maps)[mapIdx].GetFd()
		// offset / sizeof(bpfInstruction)
		idx := int(rel.Off / 8)
		if insns == nil || idx >= len(*insns) {
			return fmt.Errorf("index calculated from rel offset is greater than the instruction set; the source was probably compiled for another architecture")
		}
		ins := (*insns)[idx]
		if ins.OpCode != LdDW {
			return fmt.Errorf("the only valid relocation command is for loading a map file descriptor")
		}
		ins.SrcRegister = 1
		ins.Constant = int32(mapFd)
	}
	return nil
}
