// Package codegen contains helpers for tools generating Go code.
//
// It is kept separate from package internal since go/format and its
// dependencies would otherwise be linked and initialized in every binary
// importing the library.
package codegen

import (
	"bytes"
	"errors"
	"go/format"
	"go/scanner"
	"io"
)

// WriteFormatted outputs a formatted src into out.
//
// If formatting fails it returns an informative error message.
func WriteFormatted(src []byte, out io.Writer) error {
	formatted, err := format.Source(src)
	if err == nil {
		_, err = out.Write(formatted)
		return err
	}

	var el scanner.ErrorList
	if !errors.As(err, &el) {
		return err
	}

	var nel scanner.ErrorList
	for _, err := range el {
		if !err.Pos.IsValid() {
			nel = append(nel, err)
			continue
		}

		buf := src[err.Pos.Offset:]
		nl := bytes.IndexRune(buf, '\n')
		if nl == -1 {
			nel = append(nel, err)
			continue
		}

		err.Msg += ": " + string(buf[:nl])
		nel = append(nel, err)
	}

	return nel
}
