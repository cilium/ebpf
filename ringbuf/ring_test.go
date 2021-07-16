package ringbuf

import (
	"bytes"
	"io"
	"testing"
)

func TestRingBufferReader(t *testing.T) {
	buf := make([]byte, 2)

	ring := makeRing(2, 0)
	n, err := ring.Read(buf)
	if err != io.EOF {
		t.Error("Expected io.EOF, got", err)
	}
	if n != 2 {
		t.Errorf("Expected to read 2 bytes, got %d", n)
	}
	if !bytes.Equal(buf, []byte{0, 1}) {
		t.Error("Expected [0, 1], got", buf)
	}
	n, err = ring.Read(buf)
	if err != io.EOF {
		t.Error("Expected io.EOF, got", err)
	}
	if n != 0 {
		t.Error("Expected to read 0 bytes, got", n)
	}
}

func makeRing(size, offset int) *ringReader {
	if size != 0 && (size&(size-1)) != 0 {
		panic("size must be power of two")
	}

	ring := make([]byte, size)
	for i := range ring {
		ring[i] = byte(i)
	}

	consumer := uint64(offset)
	producer := uint64(len(ring) + offset)

	return newRingReader(&consumer, &producer, ring)
}
