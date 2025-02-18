package unsafe

import (
	"testing"

	"github.com/cilium/ebpf"
)

func TestVariablePointer(*testing.T) {
	// ensure that linkname is correct; underlying routine tested elsewhere
	VariablePointer(&ebpf.Variable{})
}
