package ebpf

import (
	"fmt"

	"github.com/cilium/ebpf/internal"
)

func resolveKconfig(_ *MapSpec) error {
	return fmt.Errorf("kconfig: %w", internal.ErrNotSupportedOnOS)
}
