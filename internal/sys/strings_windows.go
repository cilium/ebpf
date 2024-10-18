package sys

import (
	"golang.org/x/sys/windows"
)

func ByteSliceToString(s []byte) string {
	return windows.ByteSliceToString(s)
}

func ByteSliceFromString(s string) ([]byte, error) {
	return windows.ByteSliceFromString(s)
}
