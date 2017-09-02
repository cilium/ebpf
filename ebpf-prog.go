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
	maps          *[]*BPFMap
	loaded        bool
}

func NewBPFProgram(progType ProgType, instructions *Instructions, license string) (*BPFProgram, error) {
	return newBPFProgram(progType, instructions, license, 0, nil, true)
}

func newBPFProgram(progType ProgType, instructions *Instructions, license string, kernelVersion uint32, maps *[]*BPFMap, load bool) (*BPFProgram, error) {
	bpf := &BPFProgram{
		instructions:  instructions,
		kernelVersion: kernelVersion,
		license:       license,
		progType:      progType,
		maps:          maps,
	}
	if load {
		err := bpf.Load()
		if err != nil {
			return nil, err
		}
	}
	return bpf, nil
}

func (bpf *BPFProgram) Load() error {
	if bpf.loaded {
		return fmt.Errorf("bpf program already loaded")
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
		return fmt.Errorf("max instructions, %s, exceeded", MaxBPFInstructions)
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
			return fmt.Errorf("%s:\n\t%s", errnoErr(e), strings.Replace(string(logs), "\n", "\n\t", -1))
		}
		return errnoErr(e)
	}
	bpf.logs = true
	bpf.loaded = true
	return nil
}

func (bpf *BPFProgram) GetLogs() string {
	return string(bpf.logs)
}

func (bpf *BPFProgram) GetFd() int {
	return bpf.fd
}

func (bfp *BPFProgram) GetInstructions() *Instructions {
	return bpf.instructions
}

func (bpf *BPFProgram) GetKernelVersion() uint32 {
	return bpf.kernelVersion
}

func GetMaps() *[]*BPFMap {
	return bpf.maps
}

func NewBPFProgFromFile(file string) (*BPFProgram, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, nil, err
	}
	return NewBPFProgFromObjectCode(f)
}

func NewBPFProgFromObjectCode(code io.ReaderAt) (*BPFProgram, error) {
	f, err := elf.NewFile(code)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	byteOrder := f.ByteOrder
	var unProcessedSections []*elf.Section
	var license string
	var version int
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
			maps = loadMaps(byteOrder, data)
			processedSections[i] = true
		}
	}
	symbols, err = f.Symbols()
	if err != nil {
		return nil, err
	}
	for i, sec := range f.Sections {
		if !processedSections[i] && sec.Type == elf.SHT_REL && sec.Info < sectionsLen {
			sec2 := f.Sections[sec.Info]
			if sec2.Type == elf.SHT_PROGBITS ||
				sec2.Flags&elf.SHF_EXECINSTR > 0 {
				data2, err := sec2.Data()
				if err != nil {
					return nil, err
				}
				insns := loadInstructions(data)
				parseRelocateApply(data, symbols, sec, insns)
			}
		}
	}
	return nil, nil
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
	for i, l := 0, len(data); i < data; i += 4 {
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
	return &maps
}

func loadInstructions(byteOrder binary.ByteOrder, data []byte, sectionName string) *Instructions {
	var inss Instructions
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
		s := uImm & 0x80000000
		imm := int32(uImm & 0x7FFFFFFF)
		if s > 0 {
			imm = -imm
		}
		inss := append(inss, *BPFInstruction{
			OpCode:      data[i],
			DstRegister: regs.GetPart1(),
			SrcRegister: regs.GetPart2(),
			Offset:      off,
			Constant:    imm,
			sectionName: sn,
		})
	}
	return inss
}

func parseRelocateApply(byteOrder binary.ByteOrder, data []byte, symbols []elf.Symbol, sec *elf.Section, insns *Instructions, maps []*BPFMap) error {
	nRels := sec.Size / sec.Entsize
	for i, t := 0, 0; i < nRels; i++ {
		rel := elf.Rela64{
			Off:  byteOrder.Uint64(data[t : t+8]),
			Info: byteOrder.Uint64(data[t+8 : t+16]),
		}
		t += 24
		if rel.Info >= len(symbols) {
			return fmt.Errorf("index calculated from rel index is greater than the symbol set; the source was probably compiled for another architecture")
		}
		// value / sizeof(bpf_map_def)
		mapIdx := symbols[rel.Info].Value / 24
		if mapIdx >= len(maps) {
			return fmt.Errorf("index calculated from symbol value is greater than the map set; the source was probably compiled with bad symbols")
		}
		mapFd := maps[mapIdx].GetFd()
		// offset / sizeof(bpfInstruction)
		idx := rel.Off / 8
		if idx >= insns {
			return fmt.Errorf("index calculated from rel offset is greater than the instruction set; the source was probably compiled for another architecture")
		}
		ins := (*insns)[idx]
		if ins.OpCode != LdDW {
			return fmt.Errorf("the only valid relocation command is for loading a map file descriptor")
		}
		ins.SrcRegister = 1
		ins.Constant = mapFd
	}
	return nil
}
