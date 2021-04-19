package btf

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf/internal"
)

func TestParseExtInfoBigRecordSize(t *testing.T) {
	rd := strings.NewReader("\xff\xff\xff\xff\x00\x00\x00\x000709171295166016")
	table := &stringTable{[]byte("\x00"), map[string]uint32{"": 0}}
	_, err := parseExtInfo(rd, internal.NativeEndian, table)
	if err == nil {
		t.Error("Parsing ext info with large record size doesn't return an error")
	}
}
