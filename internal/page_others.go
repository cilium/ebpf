//go:build !wasm

package internal

import "os"

func Getpagesize() int {
	return os.Getpagesize()
}
