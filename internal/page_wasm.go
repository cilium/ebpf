//go:build wasm

package internal

func Getpagesize() int {
	// A WebAssembly page has a constant size of 65,536 bytes, i.e., 64KiB
	return 64 * 1024
}
