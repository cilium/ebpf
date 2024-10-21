package internal

import "fmt"

//go:generate go run golang.org/x/tools/cmd/stringer@latest -type=Platform

// Platform identifies a supported eBPF runtime.
type Platform int

const (
	UnspecifiedPlatform Platform = iota
	Linux
	Windows
)

const (
	PlatformMax   = 0xf
	PlatformShift = 24
	PlatformMask  = PlatformMax << PlatformShift
)

// Encode a [Platform] and a value into a tagged constant.
//
// The platform tag is stored in the 4 most significant bits. The tags value is
// one less than the platform constant so that Linux constants remain the same.
//
// Returns an error if either p or c are out of bounds.
func EncodePlatformConstant[T ~uint32](p Platform, c uint32) (T, error) {
	if p == UnspecifiedPlatform || p > PlatformMax {
		return 0, fmt.Errorf("invalid platform %d", p)
	}
	if c>>PlatformShift > 0 {
		return 0, fmt.Errorf("invalid constant 0x%x", c)
	}
	return T(uint32((p-1)<<PlatformShift) | c), nil
}

// Decode a [Platform] and a value from a tagged constant.
func DecodePlatformConstant[T ~uint32](c T) (Platform, uint32) {
	p := Platform(((c & PlatformMask) >> PlatformShift) + 1)
	v := uint32(c) & ^uint32(PlatformMask)
	return p, v
}
