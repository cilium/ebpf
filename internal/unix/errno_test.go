package unix

import (
	"os"
	"testing"

	"github.com/go-quicktest/qt"
)

func TestErrno(t *testing.T) {
	qt.Assert(t, qt.ErrorIs(ENOENT, os.ErrNotExist))
}
