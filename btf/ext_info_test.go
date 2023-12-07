package btf

import (
	"bytes"
	"strings"
	"testing"

	"github.com/cilium/ebpf/internal"
)

func TestParseExtInfoBigRecordSize(t *testing.T) {
	rd := strings.NewReader("\xff\xff\xff\xff\x00\x00\x00\x000709171295166016")
	table, err := readStringTable(bytes.NewReader([]byte{0}), nil)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := parseFuncInfos(rd, internal.NativeEndian, table); err == nil {
		t.Error("Parsing func info with large record size doesn't return an error")
	}

	if _, err := parseLineInfos(rd, internal.NativeEndian, table); err == nil {
		t.Error("Parsing line info with large record size doesn't return an error")
	}
}
