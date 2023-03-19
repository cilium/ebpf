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

func TestRingBufferReverseReader(t *testing.T) {
	buf := make([]byte, 4)
	expectedBuf := make([]byte, 4)
	for i := range expectedBuf {
		expectedBuf[i] = byte(i)
	}

	// First case: read 4, starting from offset 2.
	// The buffer should contain the following:
	//
	// [0 1 2 3]
	//      ^
	//      |
	//     head
	//
	// As we read from position 2, we should get [2, 3].
	// Then, when we read it for the second time, we should get [0, 1] as we would
	// have looped around the buffer.
	ring := makeOverwritableRing(4, 2)
	n, err := ring.Read(buf)
	if err != nil {
		t.Error("Expected nil, got", err)
	}
	expectedLength := len(buf) - 2
	if n != expectedLength {
		t.Errorf("Expected to read %d bytes, got %d", expectedLength, n)
	}
	if !bytes.Equal(buf[:n], expectedBuf[2:]) {
		t.Error("Expected [2 ... 4], got", buf)
	}
	n, err = ring.Read(buf)
	if err != io.EOF {
		t.Error("Expected io.EOF, got", err)
	}
	expectedLength = 2
	if n != expectedLength {
		t.Errorf("Expected to read %d bytes, got %d", expectedLength, n)
	}
	if !bytes.Equal(buf[:n], expectedBuf[:expectedLength]) {
		t.Error("Expected [0 1], got", buf)
	}

	// Complicated case: read bytes until previous_head.
	//
	// [0 1 2 3]
	//  ^   ^
	//  |   |
	//  |   +---previous_head
	// head
	//
	// So, we should read [0, 1].
	ring.meta.Data_head -= 2
	ring.loadHead()
	n, err = ring.Read(buf)
	if err != io.EOF {
		t.Error("Expected io.EOF, got", err)
	}
	if n != 2 {
		t.Error("Expected to read 2 bytes, got", n)
	}
	if !bytes.Equal(buf[:2], []byte{0, 1}) {
		t.Error("Expected [0, 1], got", buf)
	}

	// Complicated case: read the whole buffer because it was "overwritten".
	//
	// [0 1 2 3]
	//      ^
	//      |
	//      +---previous_head
	//      |
	//     head (= previous_head - len(buf))
	//
	// So, we should first read [2, ..., 255] then [0, 1].
	ring = makeOverwritableRing(4, 2)
	ring.meta.Data_head -= uint64(len(buf))
	ring.loadHead()
	n, err = ring.Read(buf)
	if err != nil {
		t.Error("Expected nil, got", err)
	}
	expectedLength = len(buf) - 2
	if n != expectedLength {
		t.Errorf("Expected to read %d bytes, got %d", expectedLength, n)
	}
	if !bytes.Equal(buf[:n], expectedBuf[2:]) {
		t.Error("Expected [2 ... 255], got", buf)
	}
	n, err = ring.Read(buf)
	if err != io.EOF {
		t.Error("Expected io.EOF, got", err)
	}
	expectedLength = 2
	if n != expectedLength {
		t.Errorf("Expected to read %d bytes, got %d", expectedLength, n)
	}
	if !bytes.Equal(buf[:n], expectedBuf[:n]) {
		t.Error("Expected [0 1], got", buf)
	}
}

func makeOverwritableRing(size, offset int) *reverseReader {
	if size != 0 && (size&(size-1)) != 0 {
		panic("size must be power of two")
	}

	ring := make([]byte, size)
	for i := range ring {
		ring[i] = byte(i)
	}

	meta := unix.PerfEventMmapPage{
		Data_head: 0 - uint64(size) - uint64(offset),
		Data_tail: 0, // never written by the kernel
		Data_size: uint64(len(ring)),
	}

	return newReverseReader(&meta, ring)
}

func makeRing(size, offset int) *forwardReader {
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

	return newForwardReader(&meta, ring)
}

func TestPerfEventRing(t *testing.T) {
	check := func(buffer, watermark int, overwritable bool) {
		ring, err := newPerfEventRing(0, buffer, watermark, overwritable)
		if err != nil {
			t.Fatal(err)
		}

		size := ring.size()

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
	_, err := newPerfEventRing(0, 8192, 8193, false)
	if err == nil {
		t.Fatal("watermark > buffer allowed")
	}
	_, err = newPerfEventRing(0, 8192, 8193, true)
	if err == nil {
		t.Fatal("watermark > buffer allowed")
	}

	// watermark == buffer
	_, err = newPerfEventRing(0, 8192, 8192, false)
	if err == nil {
		t.Fatal("watermark == buffer allowed")
	}
	_, err = newPerfEventRing(0, 8192, 8192, true)
	if err == nil {
		t.Fatal("watermark == buffer allowed")
	}

	// buffer not a power of two, watermark < buffer
	check(8193, 8192, false)
	check(8193, 8192, true)

	// large buffer not a multiple of page size at all (prime)
	check(65537, 8192, false)
	check(65537, 8192, true)
}
