package internal

import "fmt"

const (
	LinuxPlatform = "linux"
)

const (
	LinuxTag = uint32(iota) << platformShift
)

const (
	platformMax   = 0xf
	platformShift = 28
	platformMask  = platformMax << platformShift
)

func tagForPlatform(platform string) (uint32, error) {
	switch platform {
	case LinuxPlatform:
		return LinuxTag, nil
	default:
		return 0, fmt.Errorf("unrecognized platform: %s", platform)
	}
}

func platformForConstant(c uint32) string {
	tag := uint32(c & platformMask)
	switch tag {
	case LinuxTag:
		return LinuxPlatform
	default:
		return ""
	}
}

// Encode a [Platform] and a value into a tagged constant.
//
// The platform tag is stored in the 4 most significant bits. The tags value is
// one less than the platform constant so that Linux constants remain the same.
//
// Returns an error if either p or c are out of bounds.
func EncodePlatformConstant[T ~uint32](platform string, c uint32) (T, error) {
	if c>>platformShift > 0 {
		return 0, fmt.Errorf("invalid constant 0x%x", c)
	}

	tag, err := tagForPlatform(platform)
	if err != nil {
		return 0, err
	}

	return T(tag | c), nil
}

// Decode a [Platform] and a value from a tagged constant.
func DecodePlatformConstant[T ~uint32](c T) (string, uint32) {
	v := uint32(c) & ^uint32(platformMask)
	return platformForConstant(uint32(c)), v
}
