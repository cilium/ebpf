package ebpf

import (
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/kconfig"
	"github.com/cilium/ebpf/internal/linux"
	"github.com/cilium/ebpf/internal/tracefs"
)

// resolveKconfig resolves all variables declared in .kconfig and populates
// m.Contents. Does nothing if the given m.Contents is non-empty.
func resolveKconfig(m *MapSpec) error {
	ds, ok := m.Value.(*btf.Datasec)
	if !ok {
		return errors.New("map value is not a Datasec")
	}

	type configInfo struct {
		offset uint32
		typ    btf.Type
	}

	configs := make(map[string]configInfo)

	data := make([]byte, ds.Size)
	for _, vsi := range ds.Vars {
		v := vsi.Type.(*btf.Var)
		n := v.TypeName()

		switch n {
		case "LINUX_KERNEL_VERSION":
			if integer, ok := v.Type.(*btf.Int); !ok || integer.Size != 4 {
				return fmt.Errorf("variable %s must be a 32 bits integer, got %s", n, v.Type)
			}

			kv, err := linux.KernelVersion()
			if err != nil {
				return fmt.Errorf("getting kernel version: %w", err)
			}
			internal.NativeEndian.PutUint32(data[vsi.Offset:], kv.Kernel())

		case "LINUX_HAS_SYSCALL_WRAPPER":
			integer, ok := v.Type.(*btf.Int)
			if !ok {
				return fmt.Errorf("variable %s must be an integer, got %s", n, v.Type)
			}
			var value uint64 = 1
			if err := haveSyscallWrapper(); errors.Is(err, ErrNotSupported) {
				value = 0
			} else if err != nil {
				return fmt.Errorf("unable to derive a value for LINUX_HAS_SYSCALL_WRAPPER: %w", err)
			}

			if err := kconfig.PutInteger(data[vsi.Offset:], integer, value); err != nil {
				return fmt.Errorf("set LINUX_HAS_SYSCALL_WRAPPER: %w", err)
			}

		default: // Catch CONFIG_*.
			configs[n] = configInfo{
				offset: vsi.Offset,
				typ:    v.Type,
			}
		}
	}

	// We only parse kconfig file if a CONFIG_* variable was found.
	if len(configs) > 0 {
		f, err := linux.FindKConfig()
		if err != nil {
			return fmt.Errorf("cannot find a kconfig file: %w", err)
		}
		defer f.Close()

		filter := make(map[string]struct{}, len(configs))
		for config := range configs {
			filter[config] = struct{}{}
		}

		kernelConfig, err := kconfig.Parse(f, filter)
		if err != nil {
			return fmt.Errorf("cannot parse kconfig file: %w", err)
		}

		for n, info := range configs {
			value, ok := kernelConfig[n]
			if !ok {
				return fmt.Errorf("config option %q does not exists for this kernel", n)
			}

			err := kconfig.PutValue(data[info.offset:], info.typ, value)
			if err != nil {
				return fmt.Errorf("problem adding value for %s: %w", n, err)
			}
		}
	}

	m.Contents = []MapKV{{uint32(0), data}}

	return nil
}

var haveSyscallWrapper = internal.NewFeatureTest("syscall wrapper", "4.17", func() error {
	prefix := internal.PlatformPrefix()
	if prefix == "" {
		return fmt.Errorf("unable to find the platform prefix for (%s)", runtime.GOARCH)
	}

	args := tracefs.ProbeArgs{
		Type:   tracefs.Kprobe,
		Symbol: prefix + "sys_bpf",
		Pid:    -1,
	}

	var err error
	args.Group, err = tracefs.RandomGroup("ebpf_probe")
	if err != nil {
		return err
	}

	evt, err := tracefs.NewEvent(args)
	if errors.Is(err, os.ErrNotExist) {
		return internal.ErrNotSupported
	}
	if err != nil {
		return err
	}

	return evt.Close()
})
