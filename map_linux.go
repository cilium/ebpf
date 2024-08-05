package ebpf

import (
	"errors"
	"math/rand"
	"os"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf/internal/sys"
)

var mmapProtectedPage = sync.OnceValues(func() ([]byte, error) {
	return unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_NONE, unix.MAP_ANON|unix.MAP_SHARED)
})

// guessNonExistentKey attempts to perform a map lookup that returns ENOENT.
// This is necessary on kernels before 4.4.132, since those don't support
// iterating maps from the start by providing an invalid key pointer.
func guessNonExistentKey(m *Map) ([]byte, error) {
	// Map a protected page and use that as the value pointer. This saves some
	// work copying out the value, which we're not interested in.
	page, err := mmapProtectedPage()
	if err != nil {
		return nil, err
	}
	valuePtr := sys.NewSlicePointer(page)

	randKey := make([]byte, int(m.keySize))

	for i := 0; i < 4; i++ {
		switch i {
		// For hash maps, the 0 key is less likely to be occupied. They're often
		// used for storing data related to pointers, and their access pattern is
		// generally scattered across the keyspace.
		case 0:
		// An all-0xff key is guaranteed to be out of bounds of any array, since
		// those have a fixed key size of 4 bytes. The only corner case being
		// arrays with 2^32 max entries, but those are prohibitively expensive
		// in many environments.
		case 1:
			for r := range randKey {
				randKey[r] = 0xff
			}
		// Inspired by BCC, 0x55 is an alternating binary pattern (0101), so
		// is unlikely to be taken.
		case 2:
			for r := range randKey {
				randKey[r] = 0x55
			}
		// Last ditch effort, generate a random key.
		case 3:
			rand.New(rand.NewSource(time.Now().UnixNano())).Read(randKey)
		}

		err := m.lookup(randKey, valuePtr, 0)
		if errors.Is(err, ErrKeyNotExist) {
			return randKey, nil
		}
	}

	return nil, errors.New("couldn't find non-existing key")
}
