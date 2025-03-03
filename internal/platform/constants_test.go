package platform

import (
	"testing"

	"github.com/go-quicktest/qt"
)

func TestConstant(t *testing.T) {
	const maxConstant = ^uint32(platformMask)
	for _, plat := range []string{
		Linux,
	} {
		t.Run(plat, func(t *testing.T) {
			c, err := EncodeConstant[uint32](plat, maxConstant)
			qt.Assert(t, qt.IsNil(err))
			gotPlat, gotValue := DecodeConstant(c)
			qt.Assert(t, qt.Equals(gotPlat, plat))
			qt.Assert(t, qt.Equals(gotValue, maxConstant))

			_, err = EncodeConstant[uint32](plat, maxConstant+1)
			qt.Assert(t, qt.IsNotNil(err))
		})
	}
}
