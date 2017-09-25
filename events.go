// Copyright 2017 Nathan Sweet. All rights reserved.
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
package ebpf

import (
	"fmt"
	"os"
	"path"
	"strconv"
)

const (
	DebugFS      = "/sys/kernel/debug/tracing/"
	KprobeEvents = DebugFS + "kprobe_events"
	EventsDir    = DebugFS + "events"
)

const (
	_IOCNone  = 0
	_IOCWrite = 1
	_IOCRead  = 2

	_IOCNRBits   = 8
	_IOCTypeBits = 8
	_IOCSizeBits = 14

	_IOCNRShift   = 0
	_IOCTypeShift = _IOCNRShift + _IOCNRBits
	_IOCSizeShift = _IOCTypeShift + _IOCTypeBits
	_IOCDirShift  = _IOCSizeShift + _IOCSizeBits

	_IOCWriteConst = _IOCWrite << _IOCDirShift
	_IOCReadConst  = _IOCRead << _IOCDirShift
	_TypeConst     = '$' << _IOCTypeShift
	_Size64Const   = 8 << _IOCSizeShift
	_Size32Const   = 4 << _IOCSizeShift

	PerfEventIOCEnable      = _TypeConst
	PerfEventIOCDisable     = _TypeConst | 1<<_IOCNRShift
	PerfEventIOCRefresh     = _TypeConst | 2<<_IOCNRShift
	PerfEventIOCReset       = _TypeConst | 3<<_IOCNRShift
	PerfEventIOCPeriod      = _IOCWriteConst | _TypeConst | _Size64Const | 4<<_IOCNRShift
	PerfEventIOCSetOutput   = _TypeConst | 5<<_IOCNRShift
	PerfEventIOCSetFilter   = _IOCWriteConst | _TypeConst | _Size64Const | 6<<_IOCNRShift
	PerfEventIOCID          = _IOCReadConst | _TypeConst | _Size64Const | 7<<_IOCNRShift
	PerfEventIOCSetBPF      = _IOCWriteConst | _TypeConst | _Size32Const | 8<<_IOCNRShift
	PerfEventIOCPauseOutput = _IOCWriteConst | _TypeConst | _Size32Const | 9<<_IOCNRShift
)

func CreateKprobe(event string, fd BPFProgram) error {
	return createKprobe('p', "kprobe", event, fd)
}

func CreateKretprobe(event string, fd BPFProgram) error {
	return createKprobe('r', "kretprobe", event, fd)
}

func createKprobe(typ rune, base, event string, fd BPFProgram) error {
	f, err := os.OpenFile(KprobeEvents, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(fmt.Sprintf("%c:%s %s", typ, base, event))
	if err != nil {
		return err
	}
	return CreateTracepoint(event, fd)
}

func CreateTracepoint(event string, fd BPFProgram) error {
	attr := new(perfEventAttr)
	attr.perfType = 2
	attr.sampleType = 1 << 10
	attr.samplePeriod = 1
	attr.wakeupEvents = 1
	f, err := os.Open(path.Join(DebugFS, EventsDir, event))
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 256)
	_, err = f.Read(buf)
	if err != nil {
		return err
	}
	id, err := strconv.Atoi(string(buf))
	if err != nil {
		return err
	}
	attr.config = uint64(id)
	eFd, err := createPerfEvent(attr, -1, 0, -1, 0)
	err = ioctl(eFd, PerfEventIOCEnable, 0)
	if err != nil {
		return err
	}
	err = ioctl(eFd, PerfEventIOCSetBPF, fd.GetFd())
	return err
}
