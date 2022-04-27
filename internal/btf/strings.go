package btf

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

type stringTable struct {
	offsets []uint32
	strings []string
}

// sizedReader is implemented by bytes.Reader, io.SectionReader, strings.Reader, etc.
type sizedReader interface {
	io.Reader
	Size() int64
}

func readStringTable(r sizedReader) (*stringTable, error) {
	// Derived from vmlinux BTF.
	const averageStringLength = 16

	n := int(r.Size() / averageStringLength)
	offsets := make([]uint32, 0, n)
	strings := make([]string, 0, n)

	offset := uint32(0)
	scanner := bufio.NewScanner(r)
	scanner.Split(splitNull)
	for scanner.Scan() {
		str := scanner.Text()
		offsets = append(offsets, offset)
		strings = append(strings, str)
		offset += uint32(len(str)) + 1
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if len(strings) == 0 {
		return nil, errors.New("string table is empty")
	}

	if strings[0] != "" {
		return nil, errors.New("first item in string table is non-empty")
	}

	return &stringTable{offsets, strings}, nil
}

func splitNull(data []byte, atEOF bool) (advance int, token []byte, err error) {
	i := bytes.IndexByte(data, 0)
	if i == -1 {
		if atEOF && len(data) > 0 {
			return 0, nil, errors.New("string table isn't null terminated")
		}
		return 0, nil, nil
	}

	return i + 1, data[:i], nil
}

func (st *stringTable) Lookup(offset uint32) (string, error) {
	i := search(st.offsets, offset)
	if i == len(st.offsets) || st.offsets[i] != offset {
		return "", fmt.Errorf("offset %d isn't start of a string", offset)
	}

	return st.strings[i], nil
}

func (st *stringTable) Length() int {
	last := len(st.offsets) - 1
	return int(st.offsets[last]) + len(st.strings[last]) + 1
}

func (st *stringTable) Marshal(w io.Writer) error {
	for _, str := range st.strings {
		_, err := io.WriteString(w, str)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte{0})
		if err != nil {
			return err
		}
	}
	return nil
}

// search is a copy of sort.Search specialised for uint32.
//
// Licensed under https://go.dev/LICENSE
func search(ints []uint32, needle uint32) int {
	// Define f(-1) == false and f(n) == true.
	// Invariant: f(i-1) == false, f(j) == true.
	i, j := 0, len(ints)
	for i < j {
		h := int(uint(i+j) >> 1) // avoid overflow when computing h
		// i ≤ h < j
		if !(ints[h] >= needle) {
			i = h + 1 // preserves f(i-1) == false
		} else {
			j = h // preserves f(j) == true
		}
	}
	// i == j, f(i-1) == false, and f(j) (= f(i)) == true  =>  answer is i.
	return i
}

// stringTableBuilder builds BTF string tables.
type stringTableBuilder struct {
	length  uint32
	strings map[string]uint32
}

// newStringTableBuilder creates a new builder with the given initial capacity.
//
// capacity may be zero.
func newStringTableBuilder(capacity int) *stringTableBuilder {
	strings := make(map[string]uint32, capacity)
	strings[""] = 0
	return &stringTableBuilder{1, strings}
}

// Add a string to the table.
//
// Adding the same string multiple times will only store it once.
func (stb *stringTableBuilder) Add(str string) (uint32, error) {
	if strings.IndexByte(str, 0) != -1 {
		return 0, fmt.Errorf("string contains null: %q", str)
	}

	offset, ok := stb.strings[str]
	if ok {
		return offset, nil
	}

	offset = stb.length
	stb.length += uint32(len(str)) + 1
	stb.strings[str] = offset
	return offset, nil
}

// Length returns the length in bytes.
func (stb *stringTableBuilder) Length() int {
	return int(stb.length)
}

// Marshal a string table into its binary representation.
func (stb *stringTableBuilder) Marshal() []byte {
	buf := make([]byte, stb.Length())
	stb.MarshalBuffer(buf)
	return buf
}

// Marshal a string table into a pre-allocated buffer.
//
// The buffer must be at least of size Length().
func (stb *stringTableBuilder) MarshalBuffer(buf []byte) {
	for str, offset := range stb.strings {
		n := copy(buf[offset:], str)
		buf[offset+uint32(n)] = 0
	}
}
