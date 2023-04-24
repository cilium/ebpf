package tracefs

import (
	"errors"
	"os"
	"testing"
)

func TestTraceGetEventID(t *testing.T) {
	_, err := GetTraceEventID("syscalls", "sys_enter_openat")
	if err != nil {
		t.Fatal("Can't read trace event ID:", err)
	}

	_, err = GetTraceEventID("totally", "bogus")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Expected os.ErrNotExist, got", err)
	}
}
