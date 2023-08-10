package testutils

import (
	"math/rand"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

var randSeed struct {
	value int64
	once  sync.Once
}

func Rand(tb testing.TB) *rand.Rand {
	randSeed.once.Do(func() {
		randSeed.value = time.Now().UnixMicro()
	})

	seed := randSeed.value
	if seedStr, ok := os.LookupEnv("TEST_SEED"); ok {
		var err error
		seed, err = strconv.ParseInt(seedStr, 0, 64)
		if err != nil {
			tb.Fatal("Parse TEST_SEED environment variable:", err)
		}
	}

	tb.Logf("TEST_SEED=%d\n", seed)
	return rand.New(rand.NewSource(seed))
}
