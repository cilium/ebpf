package main

import (
	"bytes"
	"io"
	"os"

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

// trigger - Creates and then removes a tmp folder to trigger the probes
func trigger() error {
	logrus.Println("Generating events to trigger the probes ...")
	// Creating a tmp directory to trigger the probes
	tmpDir := "/tmp/test_folder"
	logrus.Printf("creating %v", tmpDir)
	err := os.MkdirAll(tmpDir, 0666)
	if err != nil {
		return err
	}

	// Removing a tmp directory to trigger the probes
	logrus.Printf("removing %v", tmpDir)
	return os.RemoveAll(tmpDir)
}
