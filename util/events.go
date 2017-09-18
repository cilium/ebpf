// Copyright 2017 Nathan Sweet. All rights reserved.
// Use of this source code is governed by an MIT
// license that can be found in the LICENSE file.
package util

import (
	"fmt"
	"io"
	"os"
	"path"
	"strconv"
	"syscall"
)

const (
	DebugFS      = "/sys/kernel/debug/tracing/"
	KprobeEvents = DebugFS + "kprobe_events"
	EventsDir    = DebugFS + "events"
)

func CreateKprobe(event string) error {
	return createKprobe('p', "kprobe", event)
}

func CreateKretprobe(event string) error {
	return createKprobe('r', "kretprobe", event)
}

func createKprobe(typ rune, base, event string) error {
	f, err := os.OpenFile(KprobeEvents, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	t := "p"
	if !isKprobe {
		t = "r"
	}
	err = f.WriteString(fmt.Printf("%c:%s %s", typ, base, event))
	if err != nil {
		return err
	}
}

func CreateTracepoint() error {

}

func createEvent(event string) error {
	attr := new(perfEventAttr)
	attr.perfType = 2         // tracepoint
	attr.sampleType = 1 << 10 // sample raw
	attr.samplePeriod = 1
	attr.wakeupEvents = 1
	f, err := os.Open(path.Join(DebugFS, EventsDir, event))
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 256)
	err = f.Read(buf)
	if err != nil {
		return err
	}
	id, err := strconv.Atoi(string(buf))
	if err != nil {
		return err
	}
	attr.config = id
	ptr := unsafe.Pointer(&attr)
	// http://man7.org/linux/man-pages/man2/perf_event_open.2.html
	efd, _, errNo := syscall.Syscall6(_PERF_EVENT, uintptr(ptr), -1, 0, -1, 0, 0)
	// if (efd < 0) {
	// 	printf("event %d fd %d err %s\n", id, efd, strerror(errno));
	// 	return -1;
	// }
	// event_fd[prog_cnt - 1] = efd;
	// ioctl(efd, PERF_EVENT_IOC_ENABLE, 0);
	// ioctl(efd, PERF_EVENT_IOC_SET_BPF, fd);

}

// size 104
type perfEventAttr struct {
	perfType     uint32
	size         uint32
	config       uint64
	samplePeriod uint64
	sampleType   uint64
	readFormat   uint64

	// see include/uapi/linux/
	// for details
	flags uint64

	wakeupEvents uint32
	bpType       uint32
	bpAddr       uint64
	bpLen        uint64

	sampleRegsUser  uint64
	sampleStackUser uint32
	clockId         int32

	sampleRegsIntr uint64

	auxWatermark   uint32
	sampleMaxStack uint16

	padding uint16
}
