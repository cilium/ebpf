package token

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf/internal"
	"github.com/cilium/ebpf/internal/platform"
	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

var (
	ErrTokenNotAvailable = errors.New("BPF Token is not available")
)

type Token struct {
	*sys.FD
	Mount BPFFSMount
}

// Create attempts to create a BPF token, it does so by finding all mounted BPFFS filesystems, and trying to create a
// token on each of them until it finds one that works.
//
// If a token cannot be created, it returns [ErrTokenNotAvailable]. If the OS is not Linux, it returns
// [internal.ErrNotSupportedOnOS].
func Create() (*Token, error) {
	if !platform.IsLinux {
		return nil, internal.ErrNotSupportedOnOS
	}

	mounts, err := readBPFFSMounts()
	if err != nil {
		return nil, fmt.Errorf("get bpffs mounts: %w", err)
	}

	var errs error
	for _, mount := range mounts {
		bpffsfd, err := unix.Open(mount.Path, unix.O_DIRECTORY|unix.O_RDONLY, 0)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("open bpffs mount %q: %w", mount.Path, err))
			continue
		}
		defer unix.Close(bpffsfd)

		token, err := sys.TokenCreate(&sys.TokenCreateAttr{
			BpffsFd: uint32(bpffsfd),
		})
		if err != nil {
			if errors.Is(err, unix.EINVAL) {
				errs = errors.Join(errs, fmt.Errorf(
					"token create from %q, %w (tokens not supported or mount not a BPFFS)",
					mount.Path, err))
				continue
			}

			if errors.Is(err, unix.EPERM) {
				errs = errors.Join(errs, fmt.Errorf(
					"token create from %q, %w (CAP_BPF missing or mount not owned by current user namespace)",
					mount.Path, err))
				continue
			}

			if errors.Is(err, unix.EOPNOTSUPP) {
				errs = errors.Join(errs, fmt.Errorf(
					"token create from %q, %w (cannot use token in init user namespace)",
					mount.Path, err))
				continue
			}

			if errors.Is(err, unix.ENOENT) {
				errs = errors.Join(errs, fmt.Errorf(
					"token create from %q, %w (no permissions delegated to this BPFFS)",
					mount.Path, err))
				continue
			}

			errs = errors.Join(errs, fmt.Errorf("token create from %q: %w", mount.Path, err))
			continue
		}

		return &Token{
			FD:    token,
			Mount: mount,
		}, nil
	}

	return nil, fmt.Errorf("%w: %w", ErrTokenNotAvailable, errs)
}

// BPFFSMount represents a mounted BPF filesystem. It contains information about the mount point and the permissions
// that have been delegated to it.
type BPFFSMount struct {
	Path        string
	Cmds        []sys.Cmd
	Maps        []sys.MapType
	Progs       []sys.ProgType
	AttachTypes []sys.AttachType

	mountID int
}

var readBPFFSMounts = sync.OnceValues(func() ([]BPFFSMount, error) {
	mountinfo, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer mountinfo.Close()

	var mounts []BPFFSMount

	scanner := bufio.NewScanner(mountinfo)
	// Format of /proc/self/mountinfo:
	// {id} {parent id} {major:minor} {root} {mount point} {mount options} [optional fields...] - {filesystem type} {source} {superblock options}
	for scanner.Scan() {
		line := scanner.Text()
		// Ignore the trailing newline
		if line == "" {
			continue
		}

		// Split on the dash, since we don't know the amount of optional fields, which can throw of indexes.
		firstHalfStr, secondHalfStr, ok := strings.Cut(line, "-")
		if !ok {
			return nil, fmt.Errorf("invalid mountinfo line, missing dash: %q", line)
		}

		secondHalf := strings.Fields(strings.TrimSpace(secondHalfStr))
		if len(secondHalf) < 3 {
			return nil, fmt.Errorf("invalid mountinfo line, too few fields after dash: %q", line)
		}

		fstype := secondHalf[0]
		if fstype != "bpf" {
			continue
		}

		firstHalf := strings.Fields(strings.TrimSpace(firstHalfStr))
		if len(firstHalf) < 5 {
			return nil, fmt.Errorf("invalid mountinfo line, too few fields: %q", line)
		}

		idStr := firstHalf[0]
		id, err := strconv.Atoi(idStr)
		if err != nil {
			return nil, fmt.Errorf("atoi mount id: %w", err)
		}

		mountPoint := firstHalf[4]
		superBlockOptions := secondHalf[2]

		// Remove any BPFFS mounts on the same mount point with a lower mount ID, as they would be hidden by the newer mount.
		mounts = slices.DeleteFunc(mounts, func(mnt BPFFSMount) bool {
			return mnt.Path == mountPoint && mnt.mountID < id
		})

		mount := BPFFSMount{
			Path:    mountPoint,
			mountID: id,
		}

		for o := range strings.SplitSeq(superBlockOptions, ",") {
			key, value, ok := strings.Cut(o, "=")
			if !ok {
				// Ignore options that aren't key=value, such as "ro" or "rw"
				continue
			}

			values := strings.Split(value, ":")
			switch key {
			case "delegate_cmds":
				if len(values) == 1 && values[0] == "any" {
					for i := range sys.MAX_BPF_CMD {
						mount.Cmds = append(mount.Cmds, i)
					}
					continue
				}

				for _, value := range values {
					value = "BPF_" + strings.ToUpper(value)
					cmd, err := sys.CmdFromString(value)
					if err != nil {
						return nil, fmt.Errorf("unknown cmd %q: %w", value, err)
					}
					mount.Cmds = append(mount.Cmds, cmd)
				}
			case "delegate_maps":
				if len(values) == 1 && values[0] == "any" {
					for i := range sys.MAX_BPF_MAP_TYPE {
						mount.Maps = append(mount.Maps, i)
					}
					continue
				}

				for _, value := range values {
					value = "BPF_MAP_TYPE_" + strings.ToUpper(value)
					mapType, err := sys.MapTypeFromString(value)
					if err != nil {
						return nil, fmt.Errorf("unknown map type %q: %w", value, err)
					}
					mount.Maps = append(mount.Maps, mapType)
				}
			case "delegate_progs":
				if len(values) == 1 && values[0] == "any" {
					for i := range sys.MAX_BPF_PROG_TYPE {
						mount.Progs = append(mount.Progs, i)
					}
					continue
				}

				for _, value := range values {
					value = "BPF_PROG_TYPE_" + strings.ToUpper(value)
					progType, err := sys.ProgTypeFromString(value)
					if err != nil {
						return nil, fmt.Errorf("unknown prog type %q: %w", value, err)
					}
					mount.Progs = append(mount.Progs, progType)
				}
			case "delegate_attachs":
				if len(values) == 1 && values[0] == "any" {
					for i := range sys.MAX_BPF_ATTACH_TYPE {
						mount.AttachTypes = append(mount.AttachTypes, i)
					}
					continue
				}

				for _, value := range values {
					value = "BPF_" + strings.ToUpper(value)

					attachType, err := sys.AttachTypeFromString(value)
					if err != nil {
						return nil, fmt.Errorf("unknown attach type %q: %w", value, err)
					}
					mount.AttachTypes = append(mount.AttachTypes, attachType)
				}
			}
		}

		mounts = append(mounts, mount)
	}

	return mounts, nil
})
