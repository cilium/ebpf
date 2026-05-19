package kallsyms

import (
	"bufio"
	"bytes"
	"io"
)

type reader struct {
	scanner *bufio.Scanner
	line    []byte
	field   []byte
}

func newReader(r io.Reader) *reader {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	return &reader{
		scanner: scanner,
	}
}

func (r *reader) Line() bool {
	if !r.scanner.Scan() {
		return false
	}

	r.line = r.scanner.Bytes()
	r.field = nil
	return true
}

func (r *reader) Word() bool {
	r.line = bytes.TrimLeft(r.line, " \t")

	if len(r.line) == 0 {
		r.field = nil
		return false
	}

	idx := bytes.IndexAny(r.line, " \t")
	if idx == -1 {
		r.field = r.line
		r.line = nil
		return true
	}

	r.field = r.line[:idx]
	r.line = r.line[idx+1:]
	return true
}

func (r *reader) Bytes() []byte {
	return r.field
}

func (r *reader) Text() string {
	return string(r.field)
}

func (r *reader) Err() error {
	return r.scanner.Err()
}
