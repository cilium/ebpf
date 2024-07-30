package testmain

import (
	"fmt"
	"io"
	"os"
	"sync"
)

type testingM interface {
	Run() int
}

// Run m with various debug aids enabled.
//
// The function calls [os.Exit] and does not return.
func Run(m testingM) {
	cleanup, err := startWPR()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Disabling trace logging:", err)
		cleanup = func(io.Writer) error { return nil }
	}

	fds = new(sync.Map)
	ret := m.Run()

	if fs := flushFrames(); len(fs) != 0 {
		for _, f := range fs {
			onLeakFD(f)
		}
	}

	if foundLeak.Load() {
		ret = 99
	}

	if ret == 0 {
		cleanup(nil)
	} else if err := cleanup(os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "Error while reading trace log:", err)
		ret = 99
	}

	os.Exit(ret)
}
