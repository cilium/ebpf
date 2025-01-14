package internal

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestEncodeAndDecodePlatformConstant(t *testing.T) {
	const maxConstant = ^uint32(platformMask)
	for _, plat := range []string{
		LinuxPlatform,
		WindowsPlatform,
	} {
		t.Run(plat, func(t *testing.T) {
			c, err := EncodePlatformConstant[uint32](plat, maxConstant)
			qt.Assert(t, qt.IsNil(err))
			gotPlat, gotValue := DecodePlatformConstant(c)
			qt.Assert(t, qt.Equals(gotPlat, plat))
			qt.Assert(t, qt.Equals(gotValue, maxConstant))

			_, err = EncodePlatformConstant[uint32](plat, maxConstant+1)
			qt.Assert(t, qt.IsNotNil(err))
		})
	}
}
