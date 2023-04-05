package tracefs

import (
	"fmt"
	"os"
)

type ProbeType uint8

const (
	KprobeType ProbeType = iota
	UprobeType
)

func (pt ProbeType) String() string {
	if pt == KprobeType {
		return "kprobe"
	}
	return "uprobe"
}

func (pt ProbeType) EventsFile() (*os.File, error) {
	path, err := sanitizeTracefsPath(fmt.Sprintf("%s_events", pt.String()))
	if err != nil {
		return nil, err
	}

	return os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0666)
}

type ProbeArgs struct {
	Symbol, Group, Path          string
	Offset, RefCtrOffset, Cookie uint64
	Pid, RetprobeMaxActive       int
	Ret                          bool
}
