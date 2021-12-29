//go:build armbe || mips || mips64p32
// +build armbe mips mips64p32

package sys

import "encoding/binary"

var HostByteorder = binary.BigEndian
