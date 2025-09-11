package btf

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/cilium/ebpf/internal"

	"github.com/go-quicktest/qt"
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

func BenchmarkParseLineInfoRecords(b *testing.B) {
	size := uint32(binary.Size(bpfLineInfo{}))
	count := uint32(4096)
	buf := make([]byte, size*count)

	b.ReportAllocs()

	for b.Loop() {
		parseLineInfoRecords(bytes.NewReader(buf), internal.NativeEndian, size, count, true)
	}
}

func TestParseLineInfoRecordsAllocations(t *testing.T) {
	size := uint32(binary.Size(bpfLineInfo{}))
	count := uint32(4096)
	buf := make([]byte, size*count)

	allocs := testing.AllocsPerRun(5, func() {
		parseLineInfoRecords(bytes.NewReader(buf), internal.NativeEndian, size, count, true)
	})

	// 7 is the number of allocations on go 1.22
	// what we want to test is that we are not allocating
	// once per record
	qt.Assert(t, qt.IsTrue(allocs <= 7))
}
