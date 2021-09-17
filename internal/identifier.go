package internal

import (
	"strings"
	"unicode"
)

// Identifier turns a C style type or field name into an exportable Go equivalent.
func Identifier(str string) string {
	prev := rune(-1)
	return strings.Map(func(r rune) rune {
		// See https://golang.org/ref/spec#Identifiers
		switch {
		case unicode.IsLetter(r):
			if prev == -1 {
				r = unicode.ToUpper(r)
			}

		case r == '_':
			switch {
			// The previous rune was deleted, or we are at the
			// beginning of the string.
			case prev == -1:
				fallthrough

			// The previous rune is a lower case letter or a digit.
			case unicode.IsDigit(prev) || (unicode.IsLetter(prev) && unicode.IsLower(prev)):
				// delete the current rune, and force the
				// next character to be uppercased.
				r = -1
			}

		case unicode.IsDigit(r):

		default:
			// Delete the current rune. prev is unchanged.
			return -1
		}

		prev = r
		return r
	}, str)
}
