package main

import (
	"bytes"
	"io"
	"os/exec"
	"time"

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

// trigger - Spawn a bash and execute a command to trigger the probe
func trigger() error {
	logrus.Println("Spawning a shell and executing `id` to trigger the probe ...")
	cmd := exec.Command("/usr/bin/bash", "-i")
	stdinPipe, _ := cmd.StdinPipe()
	go func() {
		io.WriteString(stdinPipe, "id")
		time.Sleep(100*time.Millisecond)
		stdinPipe.Close()
	}()
	b, err := cmd.Output()
	if err != nil {
		return err
	}
	logrus.Printf("from bash: %v", string(b))
	return nil
}

