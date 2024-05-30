package bindings

import (
	"unicode"
	"unicode/utf8"
)

func toUpperFirst(str string) string {
	first, n := utf8.DecodeRuneInString(str)
	return string(unicode.ToUpper(first)) + str[n:]
}
