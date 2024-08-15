package sys

import "golang.org/x/sys/unix"

func ByteSliceToString(s []byte) string {
	return unix.ByteSliceToString(s)
}

func ByteSliceFromString(s string) ([]byte, error) {
	return unix.ByteSliceFromString(s)
}
