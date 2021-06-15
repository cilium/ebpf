package internal

import (
	"testing"

	"github.com/cilium/ebpf/internal/unix"
)

func TestObjName(t *testing.T) {
	name := NewBPFObjName("more_than_16_characters_long")
	if name[len(name)-1] != 0 {
		t.Error("NewBPFObjName doesn't null terminate")
	}
	if len(name) != unix.BPF_OBJ_NAME_LEN {
		t.Errorf("Name is %d instead of %d bytes long", len(name), unix.BPF_OBJ_NAME_LEN)
	}
}
