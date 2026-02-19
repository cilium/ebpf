package bpffs

import (
	"errors"
	"fmt"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf/internal/sys"
	"github.com/cilium/ebpf/internal/unix"
)

const bpffsMountPath = "/sys/fs/bpf"

type BPFFS struct {
	path    string
	bpffsFd *sys.FD
	tokenFd *sys.FD
}

func NewBPFFSFromPath(path string) (*BPFFS, error) {
	if path == "" {
		path = bpffsMountPath
	} else {
		path = filepath.Clean(path)
	}

	fd, err := unix.Open(path, syscall.O_DIRECTORY|syscall.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}

	bpffsFd, err := sys.NewFD(fd)
	if err != nil {
		return nil, err
	}

	return &BPFFS{
		path:    path,
		bpffsFd: bpffsFd,
	}, nil
}

func (bf *BPFFS) Close() error {
	var errs []error

	if bf.bpffsFd != nil {
		if err := bf.bpffsFd.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if bf.tokenFd != nil {
		if err := bf.tokenFd.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (bf *BPFFS) Token() (*sys.FD, error) {
	if bf.tokenFd != nil {
		return bf.tokenFd.Dup()
	}

	if bf.bpffsFd == nil {
		return nil, fmt.Errorf("BPFFS is not mounted")
	}

	tokenAttr := sys.TokenCreateAttr{
		BpffsFd: bf.bpffsFd.Uint(),
	}

	tokenFd, err := sys.TokenCreate(&tokenAttr)
	if err != nil {
		return nil, err
	}

	bf.tokenFd = tokenFd
	return bf.tokenFd.Dup()
}
