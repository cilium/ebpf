//go:build amd64 || arm64
// +build amd64 arm64

package internal

import "encoding/binary"

var NativeEndian binary.ByteOrder = binary.LittleEndian

const ClangEndian = "el"
