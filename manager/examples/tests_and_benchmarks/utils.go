package main

import (
	"bytes"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"io"
)

// recoverAssets - Recover ebpf asset
func recoverAssets() io.ReaderAt {
	buf, err := Asset("/probe.o")
	if err != nil {
		logrus.Fatal(errors.Wrap(err, "couldn't find asset"))
	}
	return bytes.NewReader(buf)
}
