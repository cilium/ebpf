package btf

import (
	"bufio"
	"bytes"
	"io"

	"github.com/pkg/errors"
)

func readStrings(r io.Reader) (map[uint32]string, error) {
	var (
		scanner = bufio.NewScanner(r)
		strings = make(map[uint32]string)
		offset  uint32
	)

	scanner.Split(splitCString)
	for scanner.Scan() {
		str := scanner.Text()
		strings[offset] = str
		offset += uint32(len(str)) + 1
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if strings[0] != "" {
		return nil, errors.New("first item in string table is non-empty")
	}

	return strings, nil
}

func splitCString(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if len(data) == 0 {
		return 0, nil, nil
	}

	i := bytes.IndexByte(data, '\x00')
	if i == -1 {
		if atEOF {
			return 0, nil, errors.New("truncated string table")
		}
		return 0, nil, nil
	}

	// Skip trailing \0
	return i + 1, data[:i], nil
}
