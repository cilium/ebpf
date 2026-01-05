//go:build !windows

package sys

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/cilium/ebpf/internal/unix"
)

const bpffsMountPath = "/sys/fs/bpf"

var bpffsTokenByPath sync.Map

type bpffsToken struct {
	once sync.Once
	fd   *FD
	err  error
}

// bpffsGetFD return an FD for the delegated bpffs mount (e.g., /sys/fs/bpf).
func bpffsGetFD(path string) (*FD, error) {
	fd, err := unix.Open(path, syscall.O_DIRECTORY|syscall.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	return NewFD(fd)
}

// bpffsCreateTokenFD creates a bpf privilege delegation token for bpffs mount.
func bpffsCreateTokenFD(path string) (*FD, error) {
	bpffsFD, err := bpffsGetFD(path)
	if err != nil {
		return nil, fmt.Errorf("bpffs get FD from %s: %w", path, err)
	}
	defer bpffsFD.Close()

	tokenAttr := TokenCreateAttr{BpffsFd: bpffsFD.Uint()}
	tokenFD, err := TokenCreate(&tokenAttr)
	if err != nil {
		return nil, fmt.Errorf("create bpf token: %w", err)
	}
	return tokenFD, nil
}

// BpffsGetTokenFD returns created/cached bpf token for bpffs mount.
// If path is empty, the default bpffs mount path (/sys/fs/bpf) is used.
func BpffsGetTokenFD(path string) (*FD, error) {
	if path == "" {
		path = bpffsMountPath
	} else {
		path = filepath.Clean(path)
	}

	value, _ := bpffsTokenByPath.LoadOrStore(path, &bpffsToken{})
	token := value.(*bpffsToken)
	token.once.Do(func() {
		token.fd, token.err = bpffsCreateTokenFD(path)
	})

	if token.err != nil {
		return nil, token.err
	}
	return token.fd.Dup()
}

// MapCreateWithToken try to create Map, on permission issue try using bpf token.
func MapCreateWithToken(attr *MapCreateAttr) (*FD, error) {
	fd, err := MapCreate(attr)

	// On permission error try privilege delegation using BPF Token.
	if errors.Is(err, unix.EPERM) {
		if tokenFD, tokenErr := BpffsGetTokenFD(""); tokenErr == nil {
			defer tokenFD.Close()
			attr.MapTokenFd = int32(tokenFD.Int())
			attr.MapFlags |= BPF_F_TOKEN_FD
			fd, err = MapCreate(attr)
		}
	}

	return fd, err
}

// ProgLoadWithToken try to load prog, on permission issue try using bpf token.
// func ProgLoadWithToken(attr *ProgLoadAttr) (*FD, error) {
// 	fd, err := ProgLoad(attr)
//
// 	// On permission error try privilege delegation using BPF Token.
// 	if errors.Is(err, unix.EPERM) {
// 		if tokenFD, tokenErr := BpffsGetTokenFD(""); tokenErr == nil {
// 			defer tokenFD.Close()
// 			attr.ProgTokenFd = int32(tokenFD.Int())
// 			attr.ProgFlags |= BPF_F_TOKEN_FD
// 			fd, err = ProgLoad(attr)
// 		}
// 	}
//
// 	return fd, err
// }
