package sys

import (
	"bytes"
	"fmt"
	"runtime"
)

var fdMeta = make(map[int]*metadata)

type metadata struct {
	name  string
	stack *runtime.Frames
}

func (m metadata) String() string {
	return fmt.Sprintf("name '%s': created at:\n%s", m.name, formatFrames(m.stack))
}

func callersFrames() *runtime.Frames {
	c := make([]uintptr, 16)
	for {
		// Skip runtime.Callers and this function.
		i := runtime.Callers(2, c)
		if i < len(c) {
			return runtime.CallersFrames(c)
		}
		c = make([]uintptr, len(c)*2)
	}
}

func formatFrames(f *runtime.Frames) string {
	var b bytes.Buffer
	for {
		f, more := f.Next()
		b.WriteString(fmt.Sprintf("\t%s+%#x\n\t\t%s:%d\n", f.Function, f.PC-f.Entry, f.File, f.Line))
		if !more {
			break
		}
	}

	return b.String()
}
