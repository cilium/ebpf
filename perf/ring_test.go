package perf

import (
	"io"
	"os"
	"testing"

	"github.com/cilium/ebpf/internal/unix"
	qt "github.com/frankban/quicktest"
)

func TestRingBufferReader(t *testing.T) {
	ring := makeForwardRing(2, 0)
	checkRead(t, ring, []byte{0, 1}, io.EOF)
	checkRead(t, ring, []byte{}, io.EOF)

	// Wrapping read
	ring = makeForwardRing(2, 1)
	checkRead(t, ring, []byte{1}, nil)
	checkRead(t, ring, []byte{0}, io.EOF)
	checkRead(t, ring, []byte{}, io.EOF)
}

func TestRingBufferReverseReader(t *testing.T) {
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
	ring := makeReverseRing(4, 2)
	checkRead(t, ring, []byte{2, 3}, nil)
	checkRead(t, ring, []byte{0, 1}, io.EOF)
	checkRead(t, ring, []byte{}, io.EOF)

	// Complicated case: read bytes until previous_head.
	//
	// [0 1 2 3]
	//  ^   ^
	//  |   |
	//  |   +---previous_head
	// head
	ring = makeReverseRing(4, 2)
	checkReadBuffer(t, ring, []byte{2}, nil, make([]byte, 1))
	// Next read would be {3}, but we don't consume it.

	// Pretend the kernel wrote another 2 bytes.
	ring.meta.Data_head -= 2
	ring.loadHead()

	// {3} is discarded.
	checkRead(t, ring, []byte{0, 1}, io.EOF)

	// Complicated case: read the whole buffer because it was "overwritten".
	//
	// [0 1 2 3]
	//      ^
	//      |
	//      +---previous_head
	//      |
	//     head
	//
	// So, we should first read [2, 3] then [0, 1].
	ring = makeReverseRing(4, 2)
	ring.meta.Data_head -= ring.meta.Data_size
	ring.loadHead()

	checkRead(t, ring, []byte{2, 3}, nil)
	checkRead(t, ring, []byte{0, 1}, io.EOF)
}

// ensure that the next call to Read() yields the correct result.
//
// Read is called with a buffer that is larger than want so
// that corner cases around wrapping can be checked. Use
// checkReadBuffer if that is not desired.
func checkRead(t *testing.T, r io.Reader, want []byte, wantErr error) {
	checkReadBuffer(t, r, want, wantErr, make([]byte, len(want)+1))
}

func checkReadBuffer(t *testing.T, r io.Reader, want []byte, wantErr error, buf []byte) {
	t.Helper()

	n, err := r.Read(buf)
	buf = buf[:n]
	qt.Assert(t, err, qt.Equals, wantErr)
	qt.Assert(t, buf, qt.DeepEquals, want)
}

func makeBuffer(size int) []byte {
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte(i)
	}
	return buf
}

func makeReverseRing(size, offset int) *reverseReader {
	if size != 0 && (size&(size-1)) != 0 {
		panic("size must be power of two")
	}

	meta := unix.PerfEventMmapPage{
		Data_head: 0 - uint64(size) - uint64(offset),
		Data_tail: 0, // never written by the kernel
		Data_size: uint64(size),
	}

	return newReverseReader(&meta, makeBuffer(size))
}

func makeForwardRing(size, offset int) *forwardReader {
	if size != 0 && (size&(size-1)) != 0 {
		panic("size must be power of two")
	}

	meta := unix.PerfEventMmapPage{
		Data_head: uint64(size + offset),
		Data_tail: uint64(offset),
		Data_size: uint64(size),
	}

	return newForwardReader(&meta, makeBuffer(size))
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
