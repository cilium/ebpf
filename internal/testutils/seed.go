package testutils

import (
	"fmt"
	"math/rand"
	"sync"
	"time"
)

var randSeed struct {
	value int64
	once  sync.Once
}

func Rand() *rand.Rand {
	randSeed.once.Do(func() {
		randSeed.value = time.Now().UnixMicro()
		fmt.Printf("Rand is %d", randSeed.value)
	})
	return rand.New(rand.NewSource(randSeed.value))
}
