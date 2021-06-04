package link

import (
	"fmt"
	"runtime"
)

func platformPrefix(symbol string) string {

	prefix := runtime.GOARCH
	switch prefix {
	case "i386":
		prefix = "ia32"
	case "amd64":
		prefix = "x64"
	}

	return fmt.Sprintf("__%s_%s", prefix, symbol)
}
