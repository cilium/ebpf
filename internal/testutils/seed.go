package testutils

import (
	"fmt"
	"math/rand"
	"sync"
	"time"
)

type lockedCustomSource struct {
	lk sync.Mutex
	s  rand.Source
}

func Seed() {
	src := lockedCustomSource{
		lk: sync.Mutex{},
		s:  rand.NewSource(time.Now().UnixMicro()),
	}

	src.lk.Lock()
	src.s.Seed(time.Now().UnixMicro())
	src.lk.Unlock()
	fmt.Println("Seed is", src.s)
}
