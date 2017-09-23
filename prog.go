// Copyright 2017 Nathan Sweet. All rights reserved.
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
package ebpf

import (
	"fmt"
	"strings"
	"unsafe"
)

type BPFProgramSpec interface {
	ProgType() ProgType
	Instructions() *Instructions
	License() string
	KernelVersion() uint32
}

type BPFProgram int

func NewBPFProgram(progType ProgType, instructions *Instructions, license string, kernelVersion uint32) (BPFProgram, error) {
	if instructions == nil {
		return -1, fmt.Errorf("instructions can be nil")
	}
	var cInstructions []bpfInstruction
	for _, ins := range *instructions {
		inss := ins.getCStructs()
		for _, ins2 := range inss {
			cInstructions = append(cInstructions, ins2)
		}
	}
	insCount := uint32(len(cInstructions))
	if insCount > MaxBPFInstructions {
		return -1, fmt.Errorf("max instructions, %s, exceeded", MaxBPFInstructions)
	}
	lic := []byte(license)
	logs := make([]byte, LogBufSize)
	fd, e := bpfCall(_BPF_PROG_LOAD, unsafe.Pointer(&progCreateAttr{
		progType:     progType,
		insCount:     insCount,
		instructions: uint64(uintptr(unsafe.Pointer(&cInstructions[0]))),
		license:      uint64(uintptr(unsafe.Pointer(&lic[0]))),
		logLevel:     1,
		logSize:      LogBufSize,
		logBuf:       uint64(uintptr(unsafe.Pointer(&logs[0]))),
	}), 48)
	if e != 0 {
		if len(logs) > 0 {
			return -1, fmt.Errorf("%s:\n\t%s", errnoErr(e), strings.Replace(string(logs), "\n", "\n\t", -1))
		}
		return -1, errnoErr(e)
	}
	return BPFProgram(fd), nil
}

func NewBPFProgramFromSpec(spec BPFProgramSpec) (BPFProgram, error) {
	return NewBPFProgram(spec.ProgType(), spec.Instructions(), spec.License(), spec.KernelVersion())
}

func (bpf BPFProgram) GetFd() int {
	return int(bpf)
}

func (bpf BPFProgram) Pin(fileName string) error {
	return pinObject(fileName, uint32(bpf))
}

func LoadBPFProgram(fileName string) (BPFProgram, error) {
	ptr, err := getObject(fileName)
	return BPFProgram(ptr), err
}
