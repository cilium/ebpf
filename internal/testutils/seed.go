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

func Seed() rand.Source {
	randSeed.once.Do(func() {
		randSeed.value = time.Now().UnixMicro()
		fmt.Printf("Seed is %d", randSeed.value)
	})
	return rand.NewSource(randSeed.value)
}
