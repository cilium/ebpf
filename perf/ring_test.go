package perf

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/cilium/ebpf/internal/unix"
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

	// Wrapping read
	ring = makeRing(2, 1)
	n, err = io.ReadFull(ring, buf)
	if err != nil {
		t.Error("Error while reading:", err)
	}
	if n != 2 {
		t.Errorf("Expected to read 2 byte, got %d", n)
	}
	if !bytes.Equal(buf, []byte{1, 0}) {
		t.Error("Expected [1, 0], got", buf)
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

	meta := unix.PerfEventMmapPage{
		Data_head: uint64(len(ring) + offset),
		Data_tail: uint64(offset),
		Data_size: uint64(len(ring)),
	}

	return newRingReader(&meta, ring)
}

func TestPerfEventRing(t *testing.T) {
	check := func(buffer, watermark int) {
		ring, err := newPerfEventRing(0, buffer, watermark)
		if err != nil {
			t.Fatal(err)
		}

		size := len(ring.ringReader.ring)

		// Ring size should be at least as big as buffer
		if size < buffer {
			t.Fatalf("ring size %d smaller than buffer %d", size, buffer)
		}

		// Ring size should be of the form 2^n pages (meta page has already been removed)
		if size%os.Getpagesize() != 0 {
			t.Fatalf("ring size %d not whole number of pages (pageSize %d)", size, os.Getpagesize())
		}
		nPages := size / os.Getpagesize()
		if nPages&(nPages-1) != 0 {
			t.Fatalf("ring size %d (%d pages) not a power of two pages (pageSize %d)", size, nPages, os.Getpagesize())
		}
	}

	// watermark > buffer
	_, err := newPerfEventRing(0, 8192, 8193)
	if err == nil {
		t.Fatal("watermark > buffer allowed")
	}

	// watermark == buffer
	_, err = newPerfEventRing(0, 8192, 8192)
	if err == nil {
		t.Fatal("watermark == buffer allowed")
	}

	// buffer not a power of two, watermark < buffer
	check(8193, 8192)

	// large buffer not a multiple of page size at all (prime)
	check(65537, 8192)
}
