//go:build amd64 || 386 || amd64p32 || arm || mipsle || mips64p32le
// +build amd64 386 amd64p32 arm mipsle mips64p32le

package sys

import "encoding/binary"

var HostByteorder = binary.LittleEndian
