package btf

import (
	"bytes"
	"strings"
	"testing"
)

func TestStringTable(t *testing.T) {
	const in = "\x00one\x00two\x00"

	st, err := readStringTable(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := st.Marshal(&buf); err != nil {
		t.Fatal("Can't marshal string table:", err)
	}

	if !bytes.Equal([]byte(in), buf.Bytes()) {
		t.Error("String table doesn't match input")
	}

	testcases := []struct {
		offset uint32
		want   string
	}{
		{0, ""},
		{1, "one"},
		{5, "two"},
	}

	for _, tc := range testcases {
		have, err := st.Lookup(tc.offset)
		if err != nil {
			t.Errorf("Offset %d: %s", tc.offset, err)
			continue
		}

		if have != tc.want {
			t.Errorf("Offset %d: want %s but have %s", tc.offset, tc.want, have)
		}
	}

	if _, err := st.Lookup(2); err == nil {
		t.Error("No error when using offset pointing into middle of string")
	}

	// Make sure we reject bogus tables
	_, err = readStringTable(strings.NewReader("\x00one"))
	if err == nil {
		t.Fatal("Accepted non-terminated string")
	}

	_, err = readStringTable(strings.NewReader("one\x00"))
	if err == nil {
		t.Fatal("Accepted non-empty first item")
	}
}

func newStringTable(strings ...string) *stringTable {
	offsets := make([]uint32, len(strings))

	var offset uint32
	for i, str := range strings {
		offsets[i] = offset
		offset += uint32(len(str)) + 1 // account for NUL
	}

	return &stringTable{offsets, strings}
}
