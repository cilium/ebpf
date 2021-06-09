package ebpf

import (
	"testing"
	"time"
)

func TestProbeMapType(t *testing.T) {
	t1 := time.Now()
	err := ProbeMapType(Array)
	t2 := time.Now()
	if err != nil {
		t.Fatal(err)
	}

	t3 := time.Now()
	err = ProbeMapType(Array)
	t4 := time.Now()

	t.Logf("No caching: %d", t2.Sub(t1).Nanoseconds())
	t.Logf("Caching: %d", t4.Sub(t3).Nanoseconds())
}
