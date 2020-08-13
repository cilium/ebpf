package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

func stripExtension(file string) string {
	return file[:len(file)-len(filepath.Ext(file))]
}

func splitCFlagsFromArgs(in []string) (args, cflags []string) {
	for i, arg := range in {
		if arg == "--" {
			return in[:i], in[i+1:]
		}
	}

	return in, nil
}

func splitPathAbs(path string) (dir, file string, err error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}

	dir, file = filepath.Split(abs)
	return
}

func splitArguments(in string) ([]string, error) {
	var (
		result  []string
		builder strings.Builder
		escaped bool
		delim   = ' '
	)

	for _, r := range strings.TrimSpace(in) {
		if escaped {
			builder.WriteRune(r)
			escaped = false
			continue
		}

		switch r {
		case '\\':
			escaped = true

		case delim:
			current := builder.String()
			builder.Reset()

			if current != "" || delim != ' ' {
				// Only append empty words if they are not
				// delimited by spaces
				result = append(result, current)
			}
			delim = ' '

		case '"', '\'', ' ':
			if delim == ' ' {
				delim = r
				continue
			}

			fallthrough

		default:
			builder.WriteRune(r)
		}
	}

	if delim != ' ' {
		return nil, fmt.Errorf("missing `%c`", delim)
	}

	if escaped {
		return nil, errors.New("unfinished escape")
	}

	// Add the last word
	if builder.Len() > 0 {
		result = append(result, builder.String())
	}

	return result, nil
}

func toUpperFirst(str string) string {
	first, n := utf8.DecodeRuneInString(str)
	return string(unicode.ToUpper(first)) + str[n:]
}
