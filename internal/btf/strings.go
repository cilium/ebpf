package btf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
)

type stringTable struct {
	table   []byte
	offsets map[string]uint32
}

func readStringTable(r io.Reader) (*stringTable, error) {
	contents, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("can't read string table: %v", err)
	}

	if len(contents) < 1 {
		return nil, errors.New("string table is empty")
	}

	if contents[0] != '\x00' {
		return nil, errors.New("first item in string table is non-empty")
	}

	if contents[len(contents)-1] != '\x00' {
		return nil, errors.New("string table isn't null terminated")
	}

	names := bytes.Split(contents, []byte{'\x00'})
	offset := uint32(0)
	offsets := make(map[string]uint32)
	for _, name := range names {
		if int64(offset) > int64(^uint(0)>>1) {
			return nil, fmt.Errorf("offset %d overflows int", offset)
		}
		offsets[string(name)] = offset
		offset += uint32(len(name) + 1)
	}

	return &stringTable{contents, offsets}, nil
}

func (st *stringTable) Lookup(offset uint32) (string, error) {
	if int64(offset) > int64(^uint(0)>>1) {
		return "", fmt.Errorf("offset %d overflows int", offset)
	}

	pos := int(offset)
	if pos >= len(st.table) {
		return "", fmt.Errorf("offset %d is out of bounds", offset)
	}

	if pos > 0 && st.table[pos-1] != '\x00' {
		return "", fmt.Errorf("offset %d isn't start of a string", offset)
	}

	str := st.table[pos:]
	end := bytes.IndexByte(str, '\x00')
	if end == -1 {
		return "", fmt.Errorf("offset %d isn't null terminated", offset)
	}

	return string(str[:end]), nil
}

func (st *stringTable) LookupName(offset uint32) (Name, error) {
	str, err := st.Lookup(offset)
	return Name(str), err
}

func (st *stringTable) Offset(name string) uint32 {
	offset, ok := st.offsets[name]
	if ok {
		return offset
	}

	offset = uint32(len(st.table))
	st.table = append(st.table, []byte(name)...)
	st.table = append(st.table, '\x00')
	st.offsets[name] = offset

	return offset
}
