package ebpf

import (
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"github.com/cilium/ebpf/internal/sys"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMmap(t *testing.T) {
	m, err := NewMap(&MapSpec{
		Name:       "mmap",
		Type:       Array,
		KeySize:    4,
		ValueSize:  8,
		MaxEntries: 2,
		Contents: []MapKV{
			{Key: uint32(0), Value: []byte{0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}},
			{Key: uint32(1), Value: []byte{0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00}},
		},
		Flags: sys.BPF_F_MMAPABLE,
	})
	require.NoError(t, err)
	defer m.Close()

	mm, err := m.Memory()
	require.NoError(t, err)
	defer mm.close()

	// write
	w := io.NewOffsetWriter(mm, 10)
	n, err := w.Write([]byte{1, 2, 3, 4})
	require.NoError(t, err)
	assert.Equal(t, n, 4)

	// atomics
	u32, err := mm.AtomicUint32(12)
	require.NoError(t, err)
	u32.Store(0xbeef)

	fmt.Println("mmaped region:", mm.b)

	// atomic read
	require.NoError(t, err)
	assert.Equal(t, u32.Load(), uint32(0xbeef))

	// atomic add
	u32.Add(1)
	require.NoError(t, err)
	assert.EqualValues(t, u32.Load(), 0xbeef+1)

	// read
	r := io.NewSectionReader(mm, 10, 6)
	buf := make([]byte, 6)
	n, err = r.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, n, 6)
	fmt.Println("read:", buf)

	fmt.Println("dump:", hex.Dump(mm.b))
}
