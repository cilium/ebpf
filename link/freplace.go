package link

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/btf"
)

type FreplaceLink struct {
	*RawLink
}

// AttachFreplace attaches the given eBPF program to the function with the
// given name in the given target program. Example:
//
//	AttachFreplace(dispatcher, "function", replacement)
func AttachFreplace(targetProg *ebpf.Program, name string, prog *ebpf.Program) (*FreplaceLink, error) {
	if err := haveFreplace(); err != nil {
		return nil, err
	}
	if name == "" {
		return nil, fmt.Errorf("name cannot be empty: %w", errInvalidInput)
	}
	if targetProg == nil {
		return nil, fmt.Errorf("targetProg cannot be nil: %w", errInvalidInput)
	}
	if prog == nil {
		return nil, fmt.Errorf("prog cannot be nil: %w", errInvalidInput)
	}
	if prog.Type() != ebpf.Extension {
		return nil, fmt.Errorf("eBPF program type %s is not an Extension: %w", prog.Type(), errInvalidInput)
	}

	info, err := targetProg.Info()
	if err != nil {
		return nil, err
	}
	btfID, ok := info.BTFID()
	if !ok {
		return nil, fmt.Errorf("could not get BTF ID for program %s: %w", info.Name, errInvalidInput)
	}
	btfHandle, err := btf.NewHandleFromID(btfID)
	if err != nil {
		return nil, err
	}
	spec, err := btf.HandleSpec(btfHandle)
	if err != nil {
		return nil, err
	}

	var function btf.Func
	if err := spec.FindType(name, &function); err != nil {
		return nil, err
	}

	link, err := AttachRawLink(RawLinkOptions{
		Target:  targetProg.FD(),
		Program: prog,
		Attach:  ebpf.AttachNone,
		BTF:     &function,
	})
	if err != nil {
		return nil, err
	}

	return &FreplaceLink{link}, nil
}

var haveFreplace = internal.FeatureTest("freplace", "5.11", func() error {
	kv, err := internal.KernelVersion()
	if err != nil {
		return internal.ErrNotSupported
	}
	minimumKV, err := internal.NewVersion("5.11")
	if err != nil {
		return internal.ErrNotSupported
	}
	if kv.Less(minimumKV) {
		return internal.ErrNotSupported
	}
	return nil
})
