package main

import (
	"bytes"
	"io"
	"net/http"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// recoverAssets - Recover ebpf asset
func recoverAssets() io.ReaderAt {
	buf, err := Asset("/probe.o")
	if err != nil {
		logrus.Fatal(errors.Wrap(err, "couldn't find asset"))
	}
	return bytes.NewReader(buf)
}

// trigger - Generate some network traffic to trigger the probe
func trigger() {
	logrus.Println("Generating some network traffic to trigger the probes ...")
	_, _ = http.Get("https://www.google.com/")
}
