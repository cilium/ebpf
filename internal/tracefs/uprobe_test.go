package tracefs

import (
	"fmt"
	"testing"
)

func TestUprobeToken(t *testing.T) {
	tests := []struct {
		args     ProbeArgs
		expected string
	}{
		{ProbeArgs{Path: "/bin/bash"}, "/bin/bash:0x0"},
		{ProbeArgs{Path: "/bin/bash", Offset: 1}, "/bin/bash:0x1"},
		{ProbeArgs{Path: "/bin/bash", Offset: 65535}, "/bin/bash:0xffff"},
		{ProbeArgs{Path: "/bin/bash", Offset: 65536}, "/bin/bash:0x10000"},
		{ProbeArgs{Path: "/bin/bash", Offset: 1, RefCtrOffset: 1}, "/bin/bash:0x1(0x1)"},
		{ProbeArgs{Path: "/bin/bash", Offset: 1, RefCtrOffset: 65535}, "/bin/bash:0x1(0xffff)"},
	}

	for i, tt := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			po := UprobeToken(tt.args)
			if tt.expected != po {
				t.Errorf("Expected path:offset to be '%s', got '%s'", tt.expected, po)
			}
		})
	}
}
