package internal

import (
	"crypto/rand"
	"fmt"
)

// RandomTraceFSGroup generates a pseudorandom string for use as a tracefs group name.
// Returns an error when the output string would exceed 63 characters (kernel
// limitation), when rand.Read() fails or when prefix contains characters not
// allowed by isValidTraceID.
func RandomTraceFSGroup(prefix string) (string, error) {
	if !isValidTraceID(prefix) {
		return "", fmt.Errorf("prefix '%s' must be alphanumeric or underscore: %w", prefix, errInvalidInput)
	}

	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("reading random bytes: %w", err)
	}

	group := fmt.Sprintf("%s_%x", prefix, b)
	if len(group) > 63 {
		return "", fmt.Errorf("group name '%s' cannot be longer than 63 characters: %w", group, errInvalidInput)
	}

	return group, nil
}
