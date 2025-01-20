package ebpf

import (
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/efw"
)

// ProgramTypeForGUID resolves a GUID to a ProgramType.
func ProgramTypeForGUID(guid string) (ProgramType, error) {
	parsedGUID, err := windows.GUIDFromString(guid)
	if err != nil {
		return 0, fmt.Errorf("parse GUID: %w", err)
	}

	rawProgramType, err := efw.EbpfGetBpfProgramType(parsedGUID)
	if err != nil {
		return 0, err
	}

	return ProgramTypeForPlatform(internal.WindowsPlatform, rawProgramType)
}

// AttachTypeForGUID resolves a GUID to an AttachType.
func AttachTypeForGUID(guid string) (AttachType, error) {
	parsedGUID, err := windows.GUIDFromString(guid)
	if err != nil {
		return 0, fmt.Errorf("parse GUID: %w", err)
	}

	rawAttachType, err := efw.EbpfGetBpfAttachType(parsedGUID)
	if err != nil {
		return 0, err
	}

	return AttachTypeForPlatform(internal.WindowsPlatform, rawAttachType)
}
